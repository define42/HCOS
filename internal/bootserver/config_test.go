package bootserver

import (
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
