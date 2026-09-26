package bootserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Server struct {
	config   Config
	logger   *slog.Logger
	mu       sync.Mutex
	inflight map[string]chan struct{}
	builders chan struct{}
	requests chan struct{}
}

func New(config Config, logger *slog.Logger) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(config.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	info, err := os.Lstat(config.CacheDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("cache_dir must be a private directory (mode 0700)")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("cache_dir must be owned by the boot server user")
	}
	return &Server{
		config:   config,
		logger:   logger,
		inflight: make(map[string]chan struct{}),
		builders: make(chan struct{}, 2),
		requests: make(chan struct{}, 2),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/readyz", s.ready)
	mux.HandleFunc("/hcos.efi", s.boot)
	mux.HandleFunc("/boot/hcos.efi", s.boot)
	return mux
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if !allowRead(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", "3")
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, "ok\n")
	}
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if !allowRead(w, r) {
		return
	}
	if err := s.checkReady(); err != nil {
		s.logger.Error("boot server readiness failed", "error", err)
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", "6")
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, "ready\n")
	}
}

func allowRead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (s *Server) checkReady() error {
	probe, err := os.CreateTemp(s.config.CacheDir, ".ready-*")
	if err != nil {
		return fmt.Errorf("cache is not writable: %w", err)
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		os.Remove(probePath)
		return err
	}
	if err := os.Remove(probePath); err != nil {
		return err
	}
	nodes, err := loadNodes(s.config.NodesFile)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		base, agent, ca := s.config.paths(node)
		for _, path := range []string{base, agent, ca} {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() == 0 ||
				(path == agent && info.Mode().Perm()&0o111 == 0) {
				return fmt.Errorf("unavailable asset %s", path)
			}
		}
		certificate, err := readRegular(ca, 4<<20, false)
		if err != nil {
			return err
		}
		if err := validateCertificate(certificate); err != nil {
			return err
		}
	}
	if s.config.Signing != nil {
		if _, err := signingIdentity(*s.config.Signing); err != nil {
			return err
		}
	}
	if s.config.TLSCert != "" {
		for _, path := range []string{s.config.TLSCert, s.config.TLSKey} {
			if _, err := os.Stat(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) boot(w http.ResponseWriter, r *http.Request) {
	if !allowRead(w, r) {
		s.audit(r, "", nil, "", "", "", "", "", http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeID, node, err := s.resolveNode(r)
	if err != nil {
		status := http.StatusForbidden
		if !errors.Is(err, errUnauthorized) {
			status = http.StatusServiceUnavailable
		}
		s.audit(r, nodeID, nil, "", "", "", "", "", status, err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	configJSON, err := json.MarshalIndent(node.Config, "", "  ")
	if err != nil {
		s.audit(r, nodeID, &node, "", "", "", "", "", http.StatusInternalServerError, err)
		http.Error(w, "image build failed", http.StatusInternalServerError)
		return
	}
	configJSON = append(configJSON, '\n')
	configHash := sha256.Sum256(configJSON)
	revision := hex.EncodeToString(configHash[:])
	select {
	case s.requests <- struct{}{}:
	case <-r.Context().Done():
		s.audit(r, nodeID, &node, "", "", "", revision, "", http.StatusServiceUnavailable, r.Context().Err())
		http.Error(w, "request canceled", http.StatusServiceUnavailable)
		return
	}
	slotHeld := true
	defer func() {
		if slotHeld {
			<-s.requests
		}
	}()
	a, err := loadAssets(s.config, node)
	if err != nil {
		s.audit(r, nodeID, &node, "", "", "", revision, "", http.StatusServiceUnavailable, err)
		http.Error(w, "boot assets unavailable", http.StatusServiceUnavailable)
		return
	}
	baseHash, agentHash, caHash := a.hashBase(), a.hashAgent(), a.hashCA()
	signerID, err := s.signerIdentity()
	if err != nil {
		s.audit(r, nodeID, &node, baseHash, agentHash, caHash, revision, "", http.StatusServiceUnavailable, err)
		http.Error(w, "signing unavailable", http.StatusServiceUnavailable)
		return
	}
	key := imageKey(a, configHash, signerID)
	path, cacheHit, err := s.ensureImage(r.Context(), key, a, configJSON)
	if err != nil {
		s.audit(r, nodeID, &node, baseHash, agentHash, caHash, revision, "", http.StatusInternalServerError, err)
		http.Error(w, "image build failed", http.StatusInternalServerError)
		return
	}
	a = assets{}
	<-s.requests
	slotHeld = false
	file, err := os.Open(path)
	if err != nil {
		s.audit(r, nodeID, &node, baseHash, agentHash, caHash, revision, "", http.StatusInternalServerError, err)
		http.Error(w, "image unavailable", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	finalHash, err := hashOpenFile(file)
	if err != nil {
		s.audit(r, nodeID, &node, baseHash, agentHash, caHash, revision, "", http.StatusInternalServerError, err)
		http.Error(w, "image unavailable", http.StatusInternalServerError)
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		s.audit(r, nodeID, &node, baseHash, agentHash, caHash, revision, "", http.StatusInternalServerError, err)
		http.Error(w, "image unavailable", http.StatusInternalServerError)
		return
	}
	cacheStatus := "miss"
	if cacheHit {
		cacheStatus = "hit"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", `"`+hex.EncodeToString(finalHash[:])+`"`)
	recorded := &statusWriter{ResponseWriter: w}
	http.ServeContent(recorded, r, "hcos.efi", time.Time{}, file)
	status := recorded.status
	if status == 0 {
		status = http.StatusOK
	}
	s.audit(r, nodeID, &node, baseHash, agentHash, caHash, revision,
		hex.EncodeToString(finalHash[:]), status, nil, "cache", cacheStatus)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

var errUnauthorized = errors.New("unauthorized node")

func (s *Server) resolveNode(r *http.Request) (string, Node, error) {
	var empty Node
	values := r.URL.Query()
	ids := values["node"]
	tokens := values["token"]
	if len(ids) != 1 || len(tokens) != 1 || !nodeIDRE.MatchString(ids[0]) {
		return "", empty, errUnauthorized
	}
	nodes, err := loadNodes(s.config.NodesFile)
	if err != nil {
		return ids[0], empty, err
	}
	node, found := nodes[ids[0]]
	expected := "unavailable-node-placeholder-token-00000000"
	if found {
		expected = node.Config.ControllerToken
	}
	presentedHash := sha256.Sum256([]byte(tokens[0]))
	expectedHash := sha256.Sum256([]byte(expected))
	if subtle.ConstantTimeCompare(presentedHash[:], expectedHash[:]) != 1 || !found {
		return ids[0], empty, errUnauthorized
	}
	return ids[0], node, nil
}

func (s *Server) signerIdentity() ([]byte, error) {
	if s.config.Signing == nil {
		return nil, nil
	}
	return signingIdentity(*s.config.Signing)
}

func signingIdentity(c SigningConfig) ([]byte, error) {
	command, err := os.Lstat(c.Command)
	if err != nil || !command.Mode().IsRegular() || command.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("signing command is unavailable")
	}
	key, err := os.Lstat(c.Key)
	if err != nil || !key.Mode().IsRegular() || key.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("signing key is unavailable or too broadly readable")
	}
	certificate, err := readRegular(c.Certificate, 4<<20, false)
	if err != nil {
		return nil, fmt.Errorf("signing certificate: %w", err)
	}
	digest := sha256.Sum256(certificate)
	data := append([]byte(c.Revision+"\x00"), digest[:]...)
	return data, nil
}

func imageKey(a assets, configHash [32]byte, signerID []byte) string {
	hash := sha256.New()
	hash.Write([]byte("hcos-assembled-efi-v1\x00"))
	hash.Write(a.baseHash[:])
	hash.Write(a.agentHash[:])
	hash.Write(a.caHash[:])
	hash.Write(configHash[:])
	hash.Write(signerID)
	return hex.EncodeToString(hash.Sum(nil))
}

func (a assets) hashBase() string  { return hex.EncodeToString(a.baseHash[:]) }
func (a assets) hashAgent() string { return hex.EncodeToString(a.agentHash[:]) }
func (a assets) hashCA() string    { return hex.EncodeToString(a.caHash[:]) }

func (s *Server) ensureImage(ctx context.Context, key string, a assets, configJSON []byte) (string, bool, error) {
	path := filepath.Join(s.config.CacheDir, key+".efi")
	for {
		if imageExists(path) {
			return path, true, nil
		}
		s.mu.Lock()
		if wait, found := s.inflight[key]; found {
			s.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return "", false, ctx.Err()
			}
		}
		wait := make(chan struct{})
		s.inflight[key] = wait
		s.mu.Unlock()
		select {
		case s.builders <- struct{}{}:
		case <-ctx.Done():
			s.finishBuild(key, wait)
			return "", false, ctx.Err()
		}
		err := s.buildImage(ctx, path, a, configJSON)
		<-s.builders
		s.finishBuild(key, wait)
		if err != nil {
			return "", false, err
		}
		return path, false, nil
	}
}

func (s *Server) finishBuild(key string, wait chan struct{}) {
	s.mu.Lock()
	delete(s.inflight, key)
	close(wait)
	s.mu.Unlock()
}

func imageExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

func (s *Server) buildImage(ctx context.Context, final string, a assets, configJSON []byte) error {
	supplement, err := buildCPIO(configJSON, a.ca, a.agent)
	if err != nil {
		return err
	}
	image, err := AssembleEFI(a.base, supplement)
	if err != nil {
		return err
	}
	input, err := os.CreateTemp(s.config.CacheDir, ".unsigned-*.efi")
	if err != nil {
		return err
	}
	inputPath := input.Name()
	defer os.Remove(inputPath)
	if _, err = input.Write(image); err != nil {
		input.Close()
		return err
	}
	if err = input.Close(); err != nil {
		return err
	}
	candidate := inputPath
	if s.config.Signing != nil {
		output, err := os.CreateTemp(s.config.CacheDir, ".signed-*.efi")
		if err != nil {
			return err
		}
		candidate = output.Name()
		output.Close()
		os.Remove(candidate)
		defer os.Remove(candidate)
		signing := s.config.Signing
		command := exec.CommandContext(ctx, signing.Command,
			"--key", signing.Key, "--cert", signing.Certificate,
			"--output", candidate, inputPath)
		if err := command.Run(); err != nil {
			return fmt.Errorf("Secure Boot signer failed: %w", err)
		}
		if !imageExists(candidate) {
			return errors.New("Secure Boot signer returned no image")
		}
		signed, err := readRegular(candidate, 2<<30, false)
		if err != nil {
			return err
		}
		unsignedInitrd, err := InitrdSection(image)
		if err != nil {
			return err
		}
		if err := verifySignedEFI(signed, unsignedInitrd); err != nil {
			return err
		}
	}
	if err := os.Chmod(candidate, 0o400); err != nil {
		return err
	}
	if err := os.Link(candidate, final); err != nil {
		if errors.Is(err, os.ErrExist) && imageExists(final) {
			return nil
		}
		return err
	}
	return nil
}

func hashOpenFile(file *os.File) ([32]byte, error) {
	var digest [32]byte
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return digest, err
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func (s *Server) audit(r *http.Request, nodeID string, node *Node, baseHash, agentHash, caHash, configHash, finalHash string, status int, err error, extra ...any) {
	fields := []any{
		"node", nodeID, "source", r.RemoteAddr, "method", r.Method,
		"status", status, "base_sha256", baseHash, "agent_sha256", agentHash,
		"ca_sha256", caHash, "config_revision", configHash,
		"efi_sha256", finalHash, "signed", s.config.Signing != nil,
	}
	if node != nil {
		fields = append(fields, "hcos_version", node.HCOSVersion,
			"agent_version", node.AgentVersion, "ca_version", node.CAVersion)
	}
	if err != nil {
		fields = append(fields, "error", err.Error())
	}
	fields = append(fields, extra...)
	if status >= 500 {
		s.logger.Error("boot request", fields...)
	} else {
		s.logger.Info("boot request", fields...)
	}
}

// NewHTTPServer applies conservative timeouts without buffering EFI responses.
func NewHTTPServer(config Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              config.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          nil,
	}
}
