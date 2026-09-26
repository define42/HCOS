package controller

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPXEBootToken = "boot-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testPXEConfig(t *testing.T, bootURL string) PXEConfig {
	t.Helper()
	return PXEConfig{
		HTTPListenAddress: "127.0.0.1:18080",
		BootServerURL:     bootURL,
		DHCP: DHCPConfig{
			ListenAddress: "0.0.0.0:1067", Interface: "lo", ServerIP: "127.0.0.1",
			SubnetMask: "255.0.0.0", Leases: []DHCPLease{{
				NodeID: "compute-01", MAC: "52:54:00:12:34:56", IP: "127.0.0.2",
			}},
		},
		TFTP: TFTPConfig{
			ListenAddress: "127.0.0.1:1069",
		},
		BootTokens: map[string]string{"compute-01": testPXEBootToken},
	}
}

func requestPXE(handler http.Handler, method, path, remote string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	request.RemoteAddr = remote
	record := httptest.NewRecorder()
	handler.ServeHTTP(record, request)
	return record
}

func TestPXEHTTPProxiesOnlyKnownNodeWithoutExposingToken(t *testing.T) {
	image := []byte("MZpersonalized-efi")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/boot/hcos.efi" || r.URL.Query().Get("node") != "compute-01" || r.URL.Query().Get("token") != testPXEBootToken {
			http.Error(w, "wrong boot identity", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Length", "18")
		if r.Method == http.MethodGet {
			_, _ = w.Write(image)
		}
	}))
	defer upstream.Close()
	config := testPXEConfig(t, upstream.URL)
	if err := config.Validate([]NodeCredential{{ID: "compute-01", Token: strings.Repeat("n", 64)}}); err != nil {
		t.Fatalf("PXE config rejected: %v", err)
	}
	handler, err := NewPXEHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	script := requestPXE(handler, http.MethodGet, "http://127.0.0.1/boot/boot.ipxe", "127.0.0.2:1234")
	if script.Code != http.StatusOK || !bytes.HasPrefix(script.Body.Bytes(), []byte("#!ipxe\n")) || !bytes.Contains(script.Body.Bytes(), []byte("http://127.0.0.1:18080/boot/hcos.efi")) {
		t.Fatalf("unexpected iPXE script: status %d, body %q", script.Code, script.Body.String())
	}
	if bytes.Contains(script.Body.Bytes(), []byte(testPXEBootToken)) {
		t.Fatal("iPXE script disclosed boot token")
	}
	got := requestPXE(handler, http.MethodGet, "http://127.0.0.1/boot/hcos.efi", "127.0.0.2:1234")
	if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), image) {
		t.Fatalf("personalized EFI response: status %d, body %q", got.Code, got.Body.String())
	}
	head := requestPXE(handler, http.MethodHead, "http://127.0.0.1/boot/hcos.efi", "127.0.0.2:1234")
	if head.Code != http.StatusOK || head.Header().Get("Content-Length") != "18" || head.Body.Len() != 0 {
		t.Fatalf("unexpected HEAD response: status %d, length %q, body %d", head.Code, head.Header().Get("Content-Length"), head.Body.Len())
	}
	unknown := requestPXE(handler, http.MethodGet, "http://127.0.0.1/boot/hcos.efi", "127.0.0.3:1234")
	if unknown.Code != http.StatusForbidden {
		t.Fatalf("unknown source IP got HTTP %d", unknown.Code)
	}
	query := requestPXE(handler, http.MethodGet, "http://127.0.0.1/boot/hcos.efi?node=compute-01", "127.0.0.2:1234")
	if query.Code != http.StatusForbidden {
		t.Fatalf("client-supplied boot query got HTTP %d", query.Code)
	}
}

func TestPXEHTTPValidatesBootServerCA(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("MZ"))
	}))
	defer upstream.Close()
	config := testPXEConfig(t, upstream.URL)
	config.BootCAFile = filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	if err := os.WriteFile(config.BootCAFile, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	handler, err := NewPXEHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	got := requestPXE(handler, http.MethodGet, "http://127.0.0.1/boot/hcos.efi", "127.0.0.2:1234")
	if got.Code != http.StatusOK || got.Body.String() != "MZ" {
		t.Fatalf("verified TLS proxy returned HTTP %d and %q", got.Code, got.Body.String())
	}
	if err := upstream.Certificate().VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("test certificate must cover the server IP: %v", err)
	}
	if err := upstream.Certificate().VerifyHostname("localhost"); err == nil {
		t.Fatal("test certificate unexpectedly covers localhost")
	}
	config.BootServerURL = strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1)
	handler, err = NewPXEHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	mismatch := requestPXE(handler, http.MethodGet, "http://127.0.0.1/boot/hcos.efi", "127.0.0.2:1234")
	if mismatch.Code != http.StatusBadGateway {
		t.Fatalf("TLS certificate without the requested hostname returned HTTP %d, want 502", mismatch.Code)
	}
}

func TestPXERejectsMismatchedBootAssets(t *testing.T) {
	base := testPXEConfig(t, "http://127.0.0.1:8080")
	nodes := []NodeCredential{{ID: "compute-01", Token: strings.Repeat("n", 64)}}
	for _, test := range []struct {
		name string
		edit func(*PXEConfig)
	}{
		{"wrong TFTP IP", func(p *PXEConfig) { p.TFTP.ListenAddress = "127.0.0.2:1069" }},
		{"wrong DHCP boot file", func(p *PXEConfig) { p.DHCP.BootFile = "other.efi" }},
		{"wrong iPXE target", func(p *PXEConfig) { p.DHCP.IPXEBootFile = "http://127.0.0.1/other" }},
		{"missing token", func(p *PXEConfig) { p.BootTokens = map[string]string{} }},
		{"external HTTP bootserver", func(p *PXEConfig) { p.BootServerURL = "http://192.0.2.10" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.edit(&config)
			if err := config.Validate(nodes); err == nil {
				t.Fatal("mismatched PXE config accepted")
			}
		})
	}
}
