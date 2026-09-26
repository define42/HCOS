package bootserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/HCOS/internal/protocol"
)

func testServer(t *testing.T, logger *slog.Logger) (*Server, Config, Node) {
	t.Helper()
	directory := t.TempDir()
	config := Config{
		Listen:    "127.0.0.1:0",
		ImagesDir: filepath.Join(directory, "images"),
		AgentsDir: filepath.Join(directory, "agents"),
		TrustDir:  filepath.Join(directory, "trust"),
		CacheDir:  filepath.Join(directory, "cache"),
		NodesFile: filepath.Join(directory, "nodes.json"),
	}
	node := testNode()
	base, agent, ca := config.paths(node)
	for _, path := range []string{base, agent, ca} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(base, testBaseEFI(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agent, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, testCA(t), 0o644); err != nil {
		t.Fatal(err)
	}
	nodeJSON, err := json.Marshal(nodeFile{Nodes: []Node{node}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.NodesFile, nodeJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := New(config, logger)
	if err != nil {
		t.Fatal(err)
	}
	return server, config, node
}

func testNode() Node {
	return Node{
		ID:          "node-01",
		HCOSVersion: "1.0.0", AgentVersion: "1.0.0", CAVersion: "site-v1",
		Config: protocol.AgentConfig{
			APIVersion: protocol.APIVersion, NodeID: "node-01", Hostname: "node-01",
			Controller: "https://controller.internal", ControllerToken: "private-node-token-with-more-than-32-bytes",
			Storage: protocol.Storage{Path: "/vm-storage"},
			Network: protocol.Network{ManagementInterface: "eth0", VMBridge: "br-vm"},
		},
	}
}

func testCA(t *testing.T) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
}

func bootURL(node Node) string {
	return "/boot/hcos.efi?node=" + url.QueryEscape(node.ID) + "&token=" + url.QueryEscape(node.Config.ControllerToken)
}

func cacheEntries(t *testing.T, directory string) int {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".efi") && !strings.HasPrefix(entry.Name(), ".") {
			count++
		}
	}
	return count
}

func TestServerBootAndCache(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	server, config, node := testServer(t, logger)
	handler := server.Handler()
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK {
		t.Fatalf("readyz: %d", ready.Code)
	}

	request := httptest.NewRequest(http.MethodGet, bootURL(node), nil)
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request)
	if first.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", first.Code, first.Body.String())
	}
	if first.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatal("wrong EFI content type")
	}
	initrd, err := InitrdSection(first.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(initrd, []byte(node.Config.ControllerToken)) || !bytes.Contains(initrd, []byte("usr/local/bin/hcos-agent")) {
		t.Fatal("node configuration or agent missing from initramfs")
	}
	if cacheEntries(t, config.CacheDir) != 1 {
		t.Fatal("expected one cache entry")
	}
	dirInfo, err := os.Stat(config.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatal("cache directory is not private")
	}
	matches, err := filepath.Glob(filepath.Join(config.CacheDir, "*.efi"))
	if err != nil || len(matches) != 1 {
		t.Fatal("expected one final EFI")
	}
	imageInfo, err := os.Stat(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if imageInfo.Mode().Perm() != 0o400 {
		t.Fatal("cached EFI is not private")
	}

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, bootURL(node), nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD response: status=%d body=%d", head.Code, head.Body.Len())
	}
	if head.Header().Get("Content-Length") != first.Header().Get("Content-Length") {
		t.Fatal("HEAD and GET content lengths differ")
	}
	if !strings.Contains(logs.String(), `"cache":"hit"`) {
		t.Fatal("cache hit was not audited")
	}
	if strings.Contains(logs.String(), node.Config.ControllerToken) {
		t.Fatal("secret leaked into audit log")
	}

	conditional := httptest.NewRecorder()
	conditionalRequest := httptest.NewRequest(http.MethodGet, bootURL(node), nil)
	conditionalRequest.Header.Set("If-None-Match", first.Header().Get("ETag"))
	handler.ServeHTTP(conditional, conditionalRequest)
	if conditional.Code != http.StatusNotModified || conditional.Body.Len() != 0 {
		t.Fatalf("conditional request: status=%d body=%d", conditional.Code, conditional.Body.Len())
	}
	if !strings.Contains(logs.String(), `"status":304`) {
		t.Fatal("actual conditional status was not audited")
	}

	_, agent, _ := config.paths(node)
	if err := os.WriteFile(agent, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	changed := httptest.NewRecorder()
	handler.ServeHTTP(changed, httptest.NewRequest(http.MethodGet, bootURL(node), nil))
	if changed.Code != http.StatusOK || bytes.Equal(first.Body.Bytes(), changed.Body.Bytes()) {
		t.Fatal("agent change did not produce a fresh image")
	}
	if cacheEntries(t, config.CacheDir) != 2 {
		t.Fatal("asset change did not create a new cache entry")
	}

	node.Config.Registry = "new-registry.internal"
	updatedNodes, err := json.Marshal(nodeFile{Nodes: []Node{node}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.NodesFile, updatedNodes, 0o600); err != nil {
		t.Fatal(err)
	}
	updated := httptest.NewRecorder()
	handler.ServeHTTP(updated, httptest.NewRequest(http.MethodGet, bootURL(node), nil))
	if updated.Code != http.StatusOK || bytes.Equal(changed.Body.Bytes(), updated.Body.Bytes()) {
		t.Fatal("node config change did not produce a fresh image")
	}
	if cacheEntries(t, config.CacheDir) != 3 {
		t.Fatal("node config change did not create a new cache entry")
	}
}

func TestServerRejectsUnauthorizedRequests(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	server, config, node := testServer(t, logger)
	other := node
	other.ID, other.Config.NodeID = "node-02", "node-02"
	other.Config.ControllerToken = "different-node-token-with-more-than-32-bytes"
	writeTestNodes(t, config.NodesFile, node, other)
	for _, path := range []string{
		"/hcos.efi?node=node-01&token=wrong",
		"/boot/hcos.efi?node=node-01",
		"/boot/hcos.efi?node=unknown&token=" + url.QueryEscape(node.Config.ControllerToken),
		bootURL(node) + "&token=duplicate",
		"/boot/hcos.efi?node=node-02&token=" + url.QueryEscape(node.Config.ControllerToken),
		"/boot/hcos.efi?node=node-01&token=" + url.QueryEscape(other.Config.ControllerToken),
	} {
		record := httptest.NewRecorder()
		server.Handler().ServeHTTP(record, httptest.NewRequest(http.MethodGet, path, nil))
		if record.Code != http.StatusForbidden {
			t.Fatalf("unauthorized request returned status %d", record.Code)
		}
	}
	if cacheEntries(t, config.CacheDir) != 0 {
		t.Fatal("unauthorized request built an image")
	}
	for _, authorized := range []Node{node, other} {
		record := httptest.NewRecorder()
		server.Handler().ServeHTTP(record, httptest.NewRequest(http.MethodGet, bootURL(authorized), nil))
		if record.Code != http.StatusOK {
			t.Fatalf("authorized node %q returned status %d", authorized.ID, record.Code)
		}
		initrd, err := InitrdSection(record.Body.Bytes())
		if err != nil || !bytes.Contains(initrd, []byte(authorized.Config.ControllerToken)) {
			t.Fatalf("downloaded image must embed the credential used to authenticate: %v", err)
		}
		if strings.Contains(logs.String(), authorized.Config.ControllerToken) {
			t.Fatal("node token leaked into audit log")
		}
	}
	if cacheEntries(t, config.CacheDir) != 2 {
		t.Fatal("expected a separate personalized EFI for each node")
	}
}

func TestServerTokenRotationChangesDownloadAndAgentCredential(t *testing.T) {
	t.Parallel()
	server, config, node := testServer(t, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	first := httptest.NewRecorder()
	server.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodGet, bootURL(node), nil))
	if first.Code != http.StatusOK {
		t.Fatalf("initial download returned %d", first.Code)
	}
	oldURL, oldToken := bootURL(node), node.Config.ControllerToken
	node.Config.ControllerToken = strings.Repeat("!?&+/%#=", 64)
	writeTestNodes(t, config.NodesFile, node)
	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied, httptest.NewRequest(http.MethodGet, oldURL, nil))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("old token returned %d", denied.Code)
	}
	updated := httptest.NewRecorder()
	server.Handler().ServeHTTP(updated, httptest.NewRequest(http.MethodGet, bootURL(node), nil))
	if updated.Code != http.StatusOK {
		t.Fatalf("new token returned %d", updated.Code)
	}
	initrd, err := InitrdSection(updated.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// JSON escapes reserved characters such as '&'; match the encoded secret.
	encodedToken, err := json.Marshal(node.Config.ControllerToken)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(initrd, encodedToken) || bytes.Contains(initrd, []byte(oldToken)) {
		t.Fatal("token rotation did not replace the injected agent credential")
	}
	if cacheEntries(t, config.CacheDir) != 2 || bytes.Equal(first.Body.Bytes(), updated.Body.Bytes()) {
		t.Fatal("token rotation did not create a fresh personalized image")
	}
}

func TestServerConcurrentRequestsBuildOnce(t *testing.T) {
	server, config, node := testServer(t, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			record := httptest.NewRecorder()
			server.Handler().ServeHTTP(record, httptest.NewRequest(http.MethodGet, bootURL(node), nil))
			if record.Code != http.StatusOK {
				t.Errorf("status %d", record.Code)
			}
		}()
	}
	group.Wait()
	if cacheEntries(t, config.CacheDir) != 1 {
		t.Fatal("concurrent requests produced multiple cache entries")
	}
}

func TestNewRejectsPublicCacheDirectory(t *testing.T) {
	directory := t.TempDir()
	cache := filepath.Join(directory, "cache")
	if err := os.Mkdir(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		Listen: "127.0.0.1:0", ImagesDir: directory, AgentsDir: directory,
		TrustDir: directory, CacheDir: cache, NodesFile: filepath.Join(directory, "nodes.json"),
	}, nil)
	if err == nil {
		t.Fatal("public cache directory accepted")
	}
}
