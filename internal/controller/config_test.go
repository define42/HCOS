package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigValidateTransportAndCredentials(t *testing.T) {
	base := testConfig(t)
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{name: "public HTTP", change: func(c *Config) { c.ListenAddress = "0.0.0.0:8081" }},
		{name: "unspecified HTTP", change: func(c *Config) { c.ListenAddress = ":8081" }},
		{name: "missing TLS key", change: func(c *Config) { c.TLSCertFile = "/tmp/cert.pem" }},
		{name: "relative state path", change: func(c *Config) { c.StateDir = "state" }},
		{name: "filesystem root as state path", change: func(c *Config) { c.StateDir = "/" }},
		{name: "short admin token", change: func(c *Config) { c.AdminToken = "short" }},
		{name: "reused admin token", change: func(c *Config) { c.Nodes[0].Token = c.AdminToken }},
		{name: "reused node token", change: func(c *Config) { c.Nodes[1].Token = c.Nodes[0].Token }},
		{name: "bad node ID", change: func(c *Config) { c.Nodes[0].ID = "../compute" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.Nodes = append([]NodeCredential(nil), base.Nodes...)
			test.change(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
	secure := base
	secure.ListenAddress = "0.0.0.0:8443"
	secure.TLSCertFile = "/etc/hcos-controller/tls.crt"
	secure.TLSKeyFile = "/etc/hcos-controller/tls.key"
	if err := secure.Validate(); err != nil {
		t.Fatalf("HTTPS listener rejected: %v", err)
	}
}

func TestLoadConfigRejectsUnknownAndOversizedJSON(t *testing.T) {
	config := testConfig(t)
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	unknown := append([]byte(nil), data[:len(data)-1]...)
	unknown = append(unknown, []byte(`,"unexpected":true}`)...)
	if err := os.WriteFile(path, unknown, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown config field was accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", maxConfigBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("oversized config was accepted")
	}
}

func TestLoadConfigRejectsUnsafeFile(t *testing.T) {
	config := testConfig(t)
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	target := filepath.Join(root, "config.json")
	if err := os.WriteFile(target, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		mode      os.FileMode
		wantError bool
	}{
		{name: "private", mode: 0600},
		{name: "group readable", mode: 0640},
		{name: "public readable", mode: 0644, wantError: true},
		{name: "group writable", mode: 0660, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Chmod(target, test.mode); err != nil {
				t.Fatal(err)
			}
			_, err := LoadConfig(target)
			if (err != nil) != test.wantError {
				t.Fatalf("LoadConfig(mode %04o) error = %v, wantError %t", test.mode, err, test.wantError)
			}
		})
	}
	if err := os.Chmod(target, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "config-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil {
		t.Fatal("symlink to private config was accepted")
	}
	if _, err := LoadConfig(root); err == nil {
		t.Fatal("directory was accepted as config file")
	}
}
