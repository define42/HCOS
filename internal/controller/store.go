package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/define42/HCOS/internal/protocol"
)

const (
	maxDesiredBytes = 8 << 20
	maxReportBytes  = 256 << 10
)

// ErrRevisionConflict means a revision was reused for different desired content.
var ErrRevisionConflict = errors.New("desired revision already has different content")

// ErrPayloadTooLarge means canonical JSON exceeds the agent's response limit.
var ErrPayloadTooLarge = errors.New("JSON exceeds size limit")

// Store persists one desired state and one observed report per node.
// Readers see complete files because writers replace each file by rename.
type Store struct {
	root string
	mu   sync.Mutex
}

// OpenStore prepares private directories for persistent controller data.
func OpenStore(root string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, errors.New("controller store path must be a clean absolute non-root path")
	}
	for _, dir := range []string{root, filepath.Join(root, "desired"), filepath.Join(root, "reports")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("prepare controller store: %w", err)
		}
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, fmt.Errorf("inspect controller store: %w", err)
		}
		if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("controller store directory %q must be a private real directory (mode 0700)", dir)
		}
	}
	return &Store{root: root}, nil
}

// Desired returns revision zero until an administrator sets a target.
func (s *Store) Desired(ctx context.Context, nodeID string) (protocol.DesiredState, error) {
	var desired protocol.DesiredState
	if !validNodeID(nodeID) {
		return desired, errors.New("invalid node ID")
	}
	err := readJSON(ctx, s.path("desired", nodeID), maxDesiredBytes, &desired)
	if errors.Is(err, os.ErrNotExist) {
		return protocol.DesiredState{
			APIVersion: protocol.APIVersion,
			Revision:   "0",
			Domains:    []protocol.Domain{},
		}, nil
	}
	if err != nil {
		return protocol.DesiredState{}, err
	}
	if err := validateDesired(desired); err != nil {
		return protocol.DesiredState{}, fmt.Errorf("invalid stored desired state: %w", err)
	}
	if desired.Domains == nil {
		desired.Domains = []protocol.Domain{}
	}
	return desired, nil
}

// PutDesired durably replaces a node's complete desired state.
func (s *Store) PutDesired(ctx context.Context, nodeID string, desired protocol.DesiredState) error {
	if !validNodeID(nodeID) {
		return errors.New("invalid node ID")
	}
	if err := validateDesired(desired); err != nil {
		return err
	}
	if desired.Domains == nil {
		desired.Domains = []protocol.Domain{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.Desired(ctx, nodeID)
	if err != nil {
		return err
	}
	if current.Revision == desired.Revision && !reflect.DeepEqual(current, desired) {
		return ErrRevisionConflict
	}
	return writeJSON(ctx, s.path("desired", nodeID), desired, maxDesiredBytes)
}

// Report returns the latest observed report, if any.
func (s *Store) Report(ctx context.Context, nodeID string) (protocol.Report, bool, error) {
	var report protocol.Report
	if !validNodeID(nodeID) {
		return report, false, errors.New("invalid node ID")
	}
	err := readJSON(ctx, s.path("reports", nodeID), maxReportBytes, &report)
	if errors.Is(err, os.ErrNotExist) {
		return protocol.Report{}, false, nil
	}
	if err != nil {
		return protocol.Report{}, false, err
	}
	if err := validateReport(nodeID, report); err != nil {
		return protocol.Report{}, false, fmt.Errorf("invalid stored report: %w", err)
	}
	if report.Domains == nil {
		report.Domains = []protocol.DomainStatus{}
	}
	return report, true, nil
}

// PutReport durably replaces a node's latest observed report.
func (s *Store) PutReport(ctx context.Context, nodeID string, report protocol.Report) error {
	if !validNodeID(nodeID) {
		return errors.New("invalid node ID")
	}
	if err := validateReport(nodeID, report); err != nil {
		return err
	}
	if report.Domains == nil {
		report.Domains = []protocol.DomainStatus{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(ctx, s.path("reports", nodeID), report, maxReportBytes)
}

// Ready verifies that the store can still accept writes.
func (s *Store) Ready(ctx context.Context) error {
	for _, name := range []string{"desired", "reports"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir := filepath.Join(s.root, name)
		file, err := os.CreateTemp(dir, ".ready-*")
		if err != nil {
			return fmt.Errorf("controller store unavailable: %w", err)
		}
		path := file.Name()
		closeErr := file.Close()
		removeErr := os.Remove(path)
		if closeErr != nil {
			return fmt.Errorf("controller store unavailable: %w", closeErr)
		}
		if removeErr != nil {
			return fmt.Errorf("controller store unavailable: %w", removeErr)
		}
	}
	return nil
}

func (s *Store) path(kind, nodeID string) string {
	return filepath.Join(s.root, kind, nodeID+".json")
}

func readJSON(ctx context.Context, path string, limit int64, target any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errors.New("stored JSON exceeds size limit")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("stored JSON contains trailing data")
	}
	return nil
}

func writeJSON(ctx context.Context, path string, value any, limit int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := encodeJSON(value)
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return ErrPayloadTooLarge
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".write-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func encodeJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
