package controller

import (
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
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
		{name: "missing server IP", change: func(c *Config) { c.ServerIP = "" }},
		{name: "wildcard server IP", change: func(c *Config) { c.ServerIP = "0.0.0.0" }},
		{name: "IPv6 server IP", change: func(c *Config) { c.ServerIP = "::1" }},
		{name: "server IP with port", change: func(c *Config) { c.ServerIP = "127.0.0.1:9443" }},
		{name: "hostname instead of IP", change: func(c *Config) { c.ServerIP = "localhost" }},
		{name: "nonloopback without TLS", change: func(c *Config) { c.ServerIP = "192.0.2.1" }},
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
	secure.ServerIP = "192.0.2.1"
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

func TestConfigDerivesFixedServiceAddresses(t *testing.T) {
	config := testConfig(t)
	pxe := testPXEConfig(t, "http://127.0.0.1:8080")
	config.PXE = &pxe
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "boot_ca_file") {
		t.Fatalf("PXE without an HTTPS boot CA: got %v, want boot_ca_file error", err)
	}
	upstream := httptest.NewTLSServer(http.NotFoundHandler())
	defer upstream.Close()
	pxe.BootCAFile = filepath.Join(t.TempDir(), "boot-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	if err := os.WriteFile(pxe.BootCAFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("controller configuration rejected: %v", err)
	}
	if got := config.APIAddress(); got != "127.0.0.1:9443" {
		t.Fatalf("API address = %q, want 127.0.0.1:9443", got)
	}
	runtime := config.RuntimePXE()
	if runtime == nil {
		t.Fatal("enabled PXE configuration has no runtime services")
	}
	if runtime.HTTPListenAddress != "127.0.0.1:80" || runtime.TFTP.ListenAddress != "127.0.0.1:69" {
		t.Fatalf("PXE listeners = HTTP %q, TFTP %q", runtime.HTTPListenAddress, runtime.TFTP.ListenAddress)
	}
	if runtime.BootServerURL != "https://127.0.0.1:8443" {
		t.Fatalf("derived boot server URL = %q, want https://127.0.0.1:8443", runtime.BootServerURL)
	}
	if runtime.DHCP.ListenAddress != "0.0.0.0:67" || runtime.DHCP.ServerIP != config.ServerIP || runtime.DHCP.NextServerIP != config.ServerIP {
		t.Fatalf("DHCP listener and server addresses = %+v", runtime.DHCP)
	}
	dhcp, err := NewDHCPServer(runtime.DHCP)
	if err != nil {
		t.Fatalf("derived DHCP scope rejected: %v", err)
	}
	offer, ok := dhcp.HandlePacket(testDHCPRequest(1, 93, 2, 0, 9))
	if !ok {
		t.Fatal("derived DHCP scope did not offer a static lease")
	}
	if got := net.IP(offer.Packet[20:24]).String(); got != config.ServerIP {
		t.Fatalf("DHCP next-server IP = %q, want %q", got, config.ServerIP)
	}
	options := testDHCPOptions(t, offer.Packet)
	if got := net.IP(options[54]).String(); got != config.ServerIP {
		t.Fatalf("DHCP server ID = %q, want %q", got, config.ServerIP)
	}
	if got := string(options[66]); got != config.ServerIP {
		t.Fatalf("DHCP TFTP server = %q, want %q", got, config.ServerIP)
	}
	handler, err := NewPXEHandler(*runtime)
	if err != nil {
		t.Fatal(err)
	}
	if got := PXEHTTPServer(*runtime, handler).Addr; got != "127.0.0.1:80" {
		t.Fatalf("PXE HTTP server address = %q", got)
	}
	script := requestPXE(handler, http.MethodGet, "http://127.0.0.1/boot/boot.ipxe", "127.0.0.2:1234")
	want := "#!ipxe\nchain http://127.0.0.1/boot/hcos.efi\n"
	if script.Code != http.StatusOK || script.Body.String() != want {
		t.Fatalf("derived iPXE script: HTTP %d, body %q", script.Code, script.Body.String())
	}
	config.PXE = nil
	if config.RuntimePXE() != nil {
		t.Fatal("disabled PXE unexpectedly has runtime services")
	}
}

func TestLoadConfigRejectsLegacyAddressFields(t *testing.T) {
	config := testConfig(t)
	pxe := testPXEConfig(t, "http://127.0.0.1:8080")
	pxe.BootCAFile = filepath.Join(t.TempDir(), "boot-ca.pem")
	config.PXE = &pxe
	base, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, base, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("valid single-IP config rejected: %v", err)
	}
	runtime := loaded.RuntimePXE()
	if runtime == nil {
		t.Fatal("loaded PXE configuration did not enable runtime services")
	}
	if loaded.ServerIP != "127.0.0.1" || loaded.APIAddress() != "127.0.0.1:9443" || runtime.HTTPListenAddress != "127.0.0.1:80" || runtime.BootServerURL != "https://127.0.0.1:8443" {
		t.Fatalf("loaded single-IP addresses = server %q, API %q, PXE %q, boot %q", loaded.ServerIP, loaded.APIAddress(), runtime.HTTPListenAddress, runtime.BootServerURL)
	}
	cases := []struct {
		name  string
		path  []string
		field string
		value string
	}{
		{name: "controller listen_address", field: "listen_address", value: "127.0.0.1:9443"},
		{name: "PXE http_listen_address", path: []string{"pxe"}, field: "http_listen_address", value: "127.0.0.1:80"},
		{name: "PXE boot_server_url", path: []string{"pxe"}, field: "boot_server_url", value: "https://127.0.0.1:8443"},
		{name: "DHCP listen_address", path: []string{"pxe", "dhcp"}, field: "listen_address", value: "0.0.0.0:67"},
		{name: "DHCP server_ip", path: []string{"pxe", "dhcp"}, field: "server_ip", value: "127.0.0.1"},
		{name: "DHCP next_server_ip", path: []string{"pxe", "dhcp"}, field: "next_server_ip", value: "127.0.0.1"},
		{name: "TFTP listen_address", path: []string{"pxe", "tftp"}, field: "listen_address", value: "127.0.0.1:69"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(base, &document); err != nil {
				t.Fatal(err)
			}
			object := document
			for _, segment := range tc.path {
				nested, ok := object[segment].(map[string]any)
				if !ok {
					t.Fatalf("missing %s object in fixture", segment)
				}
				object = nested
			}
			object[tc.field] = tc.value
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = LoadConfig(path)
			if err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("legacy address field %q: got %v, want unknown field error", tc.field, err)
			}
		})
	}
}
