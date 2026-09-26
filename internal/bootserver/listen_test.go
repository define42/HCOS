package bootserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunSharesBootImagesOnHTTPAndHTTPS(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	server, config, node := testServer(t, slog.New(slog.NewJSONHandler(&logs, nil)))
	root := configureTestTLS(t, &config)
	config.Listen, config.PXEHTTP = "127.0.0.1:8443", true
	server.config = config

	main := newPipeListener(config.Listen)
	pxe := newPipeListener("127.0.0.1:80")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- server.run(ctx, func(_ context.Context, network, address string) (net.Listener, error) {
			if network != "tcp" {
				return nil, errors.New("unexpected listener network")
			}
			switch address {
			case main.address:
				return main, nil
			case pxe.address:
				return pxe, nil
			default:
				return nil, errors.New("unexpected listener address")
			}
		})
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		waitRun(t, done, nil)
	})
	t.Cleanup(stop)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: root},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			if address == pxe.address {
				return pxe.dial(ctx)
			}
			return main.dial(ctx)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	var firstImage []byte
	for _, origin := range []string{"https://127.0.0.1:8443", "http://127.0.0.1"} {
		for _, path := range []string{
			"/boot/hcos.efi", "/boot/hcos.efi?node=node-01&token=wrong",
			"/boot/hcos.efi?node=node-01&token=" + node.Config.ControllerToken + "&token=duplicate",
		} {
			response, err := client.Get(origin + path)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("unauthorized request returned %d", response.StatusCode)
			}
		}
		response, err := client.Get(origin + bootURL(node))
		if err != nil {
			t.Fatal(err)
		}
		image, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("boot response: status=%d error=%v", response.StatusCode, err)
		}
		if response.Header.Get("Cache-Control") != "private, no-store" {
			t.Fatal("personalized EFI must not be publicly cached")
		}
		if firstImage == nil {
			firstImage = image
		} else if !bytes.Equal(firstImage, image) {
			t.Fatal("HTTP and HTTPS listeners returned different images")
		}
	}
	if cacheEntries(t, config.CacheDir) != 1 {
		t.Fatal("both listeners must share the same image cache")
	}
	initrd, err := InitrdSection(firstImage)
	if err != nil || !bytes.Contains(initrd, []byte(node.Config.ControllerToken)) {
		t.Fatalf("missing personalized configuration: %v", err)
	}
	transport.CloseIdleConnections()
	// Wait here to inspect logs after all request handlers and serve loops exit.
	stop()
	for _, listener := range []*pipeListener{main, pxe} {
		select {
		case <-listener.closed:
		default:
			t.Fatal("listener remained open after cancellation")
		}
	}
	if strings.Contains(logs.String(), node.Config.ControllerToken) {
		t.Fatal("boot credentials leaked to logs")
	}
}

func TestRunClosesMainListenerWhenHTTPBindFails(t *testing.T) {
	t.Parallel()
	server, config, _ := testServer(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
	configureTestTLS(t, &config)
	config.Listen, config.PXEHTTP = "127.0.0.1:8443", true
	server.config = config
	main := newPipeListener(config.Listen)
	bindError := errors.New("port is occupied")
	err := server.run(t.Context(), func(_ context.Context, _, address string) (net.Listener, error) {
		if address == config.Listen {
			return main, nil
		}
		return nil, bindError
	})
	if !errors.Is(err, bindError) {
		t.Fatalf("expected bind error, got %v", err)
	}
	select {
	case <-main.closed:
	default:
		t.Fatal("main listener was not closed after HTTP bind failure")
	}
}

func TestRunStopsBothListenersWhenOneFails(t *testing.T) {
	t.Parallel()
	server, config, _ := testServer(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
	configureTestTLS(t, &config)
	config.Listen, config.PXEHTTP = "127.0.0.1:8443", true
	server.config = config
	main := newPipeListener(config.Listen)
	pxe := newPipeListener("127.0.0.1:80")
	serveError := errors.New("listener failed")
	pxe.failures <- serveError
	done := make(chan error, 1)
	go func() {
		done <- server.run(t.Context(), func(_ context.Context, _, address string) (net.Listener, error) {
			if address == config.Listen {
				return main, nil
			}
			return pxe, nil
		})
	}()
	waitRun(t, done, serveError)
	for _, listener := range []*pipeListener{main, pxe} {
		select {
		case <-listener.closed:
		default:
			t.Fatal("listener remained open after the other listener failed")
		}
	}
}

func waitRun(t *testing.T, done <-chan error, expected error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, expected) {
			t.Errorf("Run returned %v, expected %v", err, expected)
		}
	case <-time.After(5 * time.Second):
		t.Error("Run did not stop")
	}
}

func configureTestTLS(t *testing.T, config *Config) *x509.CertPool {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	config.TLSCert = filepath.Join(t.TempDir(), "server.crt")
	config.TLSKey = filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(config.TLSCert, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.TLSKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("invalid test root certificate")
	}
	return roots
}

// pipeListener lets lifecycle tests exercise real HTTP and TLS handling without
// binding privileged service ports or relying on host networking.
type pipeListener struct {
	address     string
	connections chan net.Conn
	failures    chan error
	closed      chan struct{}
	once        sync.Once
}

func newPipeListener(address string) *pipeListener {
	return &pipeListener{
		address: address, connections: make(chan net.Conn),
		failures: make(chan error, 1), closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case err := <-l.failures:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
}

func (l *pipeListener) dial(ctx context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.connections <- server:
		return client, nil
	case <-ctx.Done():
		client.Close()
		server.Close()
		return nil, ctx.Err()
	case <-l.closed:
		client.Close()
		server.Close()
		return nil, net.ErrClosed
	}
}
