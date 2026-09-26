package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/define42/HCOS/internal/protocol"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name       string
		controller string
		nodeID     string
		token      string
		storage    string
		wantError  string
	}{
		{name: "HTTPS controller", controller: "https://controller.internal", nodeID: "compute-04", token: "secret"},
		{name: "loopback HTTP", controller: "http://127.0.0.1:8080", nodeID: "compute-04", token: "secret"},
		{name: "remote HTTP rejected", controller: "http://controller.internal", nodeID: "compute-04", token: "secret", wantError: "HTTPS"},
		{name: "URL credentials rejected", controller: "https://user:pass@controller.internal", nodeID: "compute-04", token: "secret", wantError: "invalid controller URL"},
		{name: "invalid node ID", controller: "https://controller.internal", nodeID: "../other", token: "secret", wantError: "invalid node ID"},
		{name: "missing token", controller: "https://controller.internal", nodeID: "compute-04", wantError: "controller token"},
		{name: "relative storage", controller: "https://controller.internal", nodeID: "compute-04", token: "secret", storage: "vm-storage", wantError: "storage path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := protocol.AgentConfig{
				APIVersion: protocol.APIVersion, NodeID: tt.nodeID,
				Controller: tt.controller, ControllerToken: tt.token,
				Storage: protocol.Storage{Path: tt.storage},
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			_, _, err = loadConfig(path)
			if tt.wantError == "" && err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("loadConfig error = %v, want %q", err, tt.wantError)
			}
		})
	}
}
