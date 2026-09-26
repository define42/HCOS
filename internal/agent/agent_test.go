package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/HCOS/internal/protocol"
)

const testDomainXML = `<domain type='kvm'><name>guest-1</name><os><type arch='x86_64'>hvm</type></os><devices><emulator>/usr/bin/qemu-system-x86_64</emulator></devices></domain>`

type controllerFixture struct {
	mu      sync.Mutex
	desired protocol.DesiredState
	reports []protocol.Report
}

func newTestAgent(t *testing.T, desired protocol.DesiredState, storagePath string) (*Agent, *controllerFixture, string) {
	t.Helper()
	fixture := &controllerFixture{desired: desired}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/nodes/node-1/desired":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(fixture.desired)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/nodes/node-1/report":
			var report protocol.Report
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				http.Error(w, "invalid report", http.StatusBadRequest)
				return
			}
			fixture.reports = append(fixture.reports, report)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := protocol.AgentConfig{
		APIVersion: protocol.APIVersion, NodeID: "node-1", Hostname: "node-1",
		Controller: server.URL, ControllerToken: "test-token",
		Storage: protocol.Storage{Path: storagePath},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	virshPath := filepath.Join(dir, "virsh")
	const virshScript = `#!/bin/sh
set -eu
[ "$1" = "-c" ] && [ "$2" = "qemu:///system" ]
printf '%s\n' "$3" >> "$HCOS_FAKE_DIR/calls"
case "$3" in
  define) [ -f "$4" ]; [ -f "$HCOS_FAKE_DIR/state" ] || printf 'shut off\n' > "$HCOS_FAKE_DIR/state" ;;
  domstate) cat "$HCOS_FAKE_DIR/state" ;;
  start|resume) printf 'running\n' > "$HCOS_FAKE_DIR/state" ;;
  shutdown) printf 'shut off\n' > "$HCOS_FAKE_DIR/state" ;;
  *) exit 12 ;;
esac
`
	if err := os.WriteFile(virshPath, []byte(virshScript), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HCOS_FAKE_DIR", dir)
	a, err := New(Options{
		ConfigPath: configPath, CAPath: ca, VirshPath: virshPath,
		PollInterval: 10 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return a, fixture, dir
}

func TestAgent_Sync(t *testing.T) {
	desired := protocol.DesiredState{
		APIVersion: protocol.APIVersion, Revision: "revision-1",
		Domains: []protocol.Domain{{Name: "guest-1", XML: testDomainXML, Running: true}},
	}
	a, fixture, dir := newTestAgent(t, desired, "")
	ctx := context.Background()
	if err := a.Sync(ctx); err != nil {
		t.Fatalf("start guest: %v", err)
	}
	if err := a.Sync(ctx); err != nil {
		t.Fatalf("steady state: %v", err)
	}
	fixture.mu.Lock()
	fixture.desired.Domains[0].Running = false
	fixture.mu.Unlock()
	if err := a.Sync(ctx); err != nil {
		t.Fatalf("shutdown guest: %v", err)
	}
	fixture.mu.Lock()
	fixture.desired.Domains = nil
	fixture.mu.Unlock()
	if err := a.Sync(ctx); err != nil {
		t.Fatalf("absent guest must not be deleted: %v", err)
	}
	calls, err := os.ReadFile(filepath.Join(dir, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(calls)
	if strings.Count(got, "define\n") != 1 || strings.Count(got, "start\n") != 1 || strings.Count(got, "shutdown\n") != 1 {
		t.Fatalf("unexpected virsh calls: %q", got)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.reports) != 4 {
		t.Fatalf("got %d reports, want 4", len(fixture.reports))
	}
	if first := fixture.reports[0]; first.NodeID != "node-1" || first.Revision != "revision-1" || first.Error != "" || len(first.Domains) != 1 || first.Domains[0].State != "running" {
		t.Fatalf("unexpected first report: %+v", first)
	}
	if shutdown := fixture.reports[2]; len(shutdown.Domains) != 1 || shutdown.Domains[0].State != "shut off" {
		t.Fatalf("unexpected shutdown report: %+v", shutdown)
	}
	if len(fixture.reports[3].Domains) != 0 {
		t.Fatalf("absent domain was reported as managed: %+v", fixture.reports[3])
	}
}

func TestAgent_SyncRejectsInvalidDesiredBeforeMutation(t *testing.T) {
	desired := protocol.DesiredState{
		APIVersion: protocol.APIVersion, Revision: "revision-1",
		Domains: []protocol.Domain{{Name: "guest-1", XML: strings.Replace(testDomainXML, "x86_64'>", "aarch64'>", 1), Running: true}},
	}
	a, fixture, dir := newTestAgent(t, desired, "")
	if err := a.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "x86_64") {
		t.Fatalf("Sync error = %v, want x86_64 validation error", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "calls")); !os.IsNotExist(err) {
		t.Fatalf("virsh called for invalid desired state: %v", err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.reports) != 1 || !strings.Contains(fixture.reports[0].Error, "x86_64") {
		t.Fatalf("missing validation report: %+v", fixture.reports)
	}
}

func TestAgent_SyncRequiresMountedStorageBeforeStart(t *testing.T) {
	desired := protocol.DesiredState{
		APIVersion: protocol.APIVersion, Revision: "revision-1",
		Domains: []protocol.Domain{{Name: "guest-1", XML: testDomainXML, Running: true}},
	}
	storage := filepath.Join(t.TempDir(), "vm-storage")
	a, fixture, dir := newTestAgent(t, desired, storage)
	if err := a.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "not mounted") {
		t.Fatalf("Sync error = %v, want missing mount error", err)
	}
	calls, err := os.ReadFile(filepath.Join(dir, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "start\n") {
		t.Fatalf("started guest without storage mount: %q", calls)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.reports) != 1 || !strings.Contains(fixture.reports[0].Error, "not mounted") {
		t.Fatalf("missing storage report: %+v", fixture.reports)
	}
}
