package bootserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigPXEHTTP(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		listen string
		tls    bool
		valid  bool
	}{
		{name: "provisioning address", listen: "192.168.50.2:8443", tls: true, valid: true},
		{name: "loopback", listen: "127.0.0.1:8443", tls: true, valid: true},
		{name: "missing TLS", listen: "127.0.0.1:8443"},
		{name: "wildcard", listen: "0.0.0.0:8443", tls: true},
		{name: "empty host", listen: ":8443", tls: true},
		{name: "hostname", listen: "boot.internal:8443", tls: true},
		{name: "IPv6", listen: "[::1]:8443", tls: true},
		{name: "multicast", listen: "224.0.0.1:8443", tls: true},
		{name: "broadcast", listen: "255.255.255.255:8443", tls: true},
		{name: "missing port", listen: "192.168.50.2", tls: true},
		{name: "HTTP port conflict", listen: "192.168.50.2:80", tls: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := Config{
				Listen: test.listen, PXEHTTP: true,
				ImagesDir: "/images", AgentsDir: "/agents", TrustDir: "/trust",
				CacheDir: "/cache", NodesFile: "/nodes.json",
			}
			if test.tls {
				config.TLSCert, config.TLSKey = "/server.crt", "/server.key"
			}
			err := config.Validate()
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && (err == nil || !strings.Contains(err.Error(), "pxe_http")) {
				t.Fatalf("expected pxe_http validation error, got %v", err)
			}
		})
	}
}

func TestNodeControllerTokenValidation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		token string
		valid bool
	}{
		{name: "minimum length", token: strings.Repeat("a", 32), valid: true},
		{name: "maximum length", token: strings.Repeat("a", 512), valid: true},
		{name: "reserved characters", token: strings.Repeat("!~&?+%/#=", 4), valid: true},
		{name: "empty"},
		{name: "too short", token: strings.Repeat("a", 31)},
		{name: "too long", token: strings.Repeat("a", 513)},
		{name: "space", token: strings.Repeat("a", 31) + " "},
		{name: "tab", token: strings.Repeat("a", 31) + "\t"},
		{name: "newline", token: strings.Repeat("a", 31) + "\n"},
		{name: "DEL", token: strings.Repeat("a", 31) + "\x7f"},
		{name: "Unicode", token: strings.Repeat("a", 31) + "é"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			node := testNode()
			node.Config.ControllerToken = test.token
			err := node.validate()
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && (err == nil || !strings.Contains(err.Error(), "config.controller_token")) {
				t.Fatalf("expected controller_token validation error, got %v", err)
			}
			if err != nil && test.token != "" && strings.Contains(err.Error(), test.token) {
				t.Fatal("validation error contains the token")
			}
		})
	}
}

func TestLoadNodesRejectsSharedControllerToken(t *testing.T) {
	t.Parallel()
	first := testNode()
	second := first
	second.ID, second.Config.NodeID = "node-02", "node-02"
	path := filepath.Join(t.TempDir(), "nodes.json")
	writeTestNodes(t, path, first, second)
	_, err := loadNodes(path)
	if err == nil || !strings.Contains(err.Error(), "must have different config.controller_token") {
		t.Fatalf("expected duplicate token rejection, got %v", err)
	}
	if strings.Contains(err.Error(), first.Config.ControllerToken) {
		t.Fatal("duplicate token error contains the token")
	}
	second.Config.ControllerToken = "different-node-token-with-more-than-32-bytes"
	writeTestNodes(t, path, first, second)
	if nodes, err := loadNodes(path); err != nil || len(nodes) != 2 {
		t.Fatalf("distinct node tokens rejected: nodes=%d error=%v", len(nodes), err)
	}
}

func TestLoadNodesRejectsLegacyBootToken(t *testing.T) {
	t.Parallel()
	node := testNode()
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["boot_token"] = node.Config.ControllerToken
	data, err = json.Marshal(map[string]any{"nodes": []any{legacy}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = loadNodes(path)
	if err == nil || !strings.Contains(err.Error(), `unknown field "boot_token"`) {
		t.Fatalf("expected legacy boot_token rejection, got %v", err)
	}
}

func writeTestNodes(t *testing.T, path string, nodes ...Node) {
	t.Helper()
	data, err := json.Marshal(nodeFile{Nodes: nodes})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
