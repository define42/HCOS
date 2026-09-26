package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/define42/HCOS/internal/protocol"
)

var identifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

// Options describes the local resources the agent uses. The defaults belong to
// the CLI so tests and other callers can supply isolated paths.
type Options struct {
	ConfigPath   string
	CAPath       string
	VirshPath    string
	PollInterval time.Duration
}

func loadConfig(path string) (protocol.AgentConfig, *url.URL, error) {
	var cfg protocol.AgentConfig
	file, err := os.Open(path)
	if err != nil {
		return cfg, nil, fmt.Errorf("open agent config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return cfg, nil, fmt.Errorf("read agent config: %w", err)
	}
	if len(data) > 1<<20 {
		return cfg, nil, errors.New("agent config exceeds 1 MiB")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, nil, fmt.Errorf("decode agent config: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return cfg, nil, errors.New("agent config must contain one JSON object")
	}
	if cfg.APIVersion != protocol.APIVersion {
		return cfg, nil, fmt.Errorf("unsupported agent API version %q", cfg.APIVersion)
	}
	if !identifierRE.MatchString(cfg.NodeID) {
		return cfg, nil, errors.New("invalid node ID")
	}
	if cfg.ControllerToken == "" || strings.ContainsAny(cfg.ControllerToken, " \t\r\n") {
		return cfg, nil, errors.New("controller token is missing or malformed")
	}
	if cfg.Storage.Path != "" && (!filepath.IsAbs(cfg.Storage.Path) || filepath.Clean(cfg.Storage.Path) != cfg.Storage.Path || cfg.Storage.Path == "/") {
		return cfg, nil, errors.New("storage path must be a clean absolute mount point")
	}
	u, err := url.Parse(cfg.Controller)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return cfg, nil, errors.New("invalid controller URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return cfg, nil, errors.New("controller URL must use HTTPS except for loopback")
	}
	return cfg, u, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newHTTPClient(caPath string) (*http.Client, error) {
	file, err := os.Open(caPath)
	if err != nil {
		return nil, fmt.Errorf("open controller CA: %w", err)
	}
	defer file.Close()
	cert, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return nil, fmt.Errorf("read controller CA: %w", err)
	}
	if len(cert) > 1<<20 {
		return nil, errors.New("controller CA exceeds 1 MiB")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		return nil, errors.New("controller CA contains no PEM certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}
