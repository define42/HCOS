// Package controller serves revisioned desired state to HCOS agents.
package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
)

const (
	maxConfigBytes = 1 << 20
	apiPort        = "9443"
	pxeHTTPPort    = "80"
	pxeTFTPPort    = "69"
	dhcpAddress    = "0.0.0.0:67"
)

// Config is the controller's local JSON configuration. Tokens are never logged.
type Config struct {
	ServerIP    string           `json:"server_ip"`
	TLSCertFile string           `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string           `json:"tls_key_file,omitempty"`
	StateDir    string           `json:"state_dir"`
	AdminToken  string           `json:"admin_token"`
	Nodes       []NodeCredential `json:"nodes"`
	PXE         *PXEConfig       `json:"pxe,omitempty"`
}

// APIAddress is the controller API listener on the configured IP.
func (c Config) APIAddress() string {
	return net.JoinHostPort(c.ServerIP, apiPort)
}

// RuntimePXE fills in the fixed listener and advertised addresses. DHCP binds
// the provisioning interface on all IPv4 addresses to receive broadcasts.
func (c Config) RuntimePXE() *PXEConfig {
	if c.PXE == nil {
		return nil
	}
	pxe := *c.PXE
	pxe.HTTPListenAddress = net.JoinHostPort(c.ServerIP, pxeHTTPPort)
	pxe.DHCP.ListenAddress = dhcpAddress
	pxe.DHCP.ServerIP = c.ServerIP
	pxe.DHCP.NextServerIP = c.ServerIP
	pxe.TFTP.ListenAddress = net.JoinHostPort(c.ServerIP, pxeTFTPPort)
	return &pxe
}

// NodeCredential binds one agent bearer token to one node ID.
type NodeCredential struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// LoadConfig reads a bounded, strict JSON configuration file.
func LoadConfig(path string) (Config, error) {
	var config Config
	info, err := os.Lstat(path)
	if err != nil {
		return config, fmt.Errorf("inspect controller config: %w", err)
	}
	if !safeConfigFile(info) {
		return config, errors.New("controller config must be a regular file without public access or group write permission")
	}
	file, err := os.Open(path)
	if err != nil {
		return config, fmt.Errorf("open controller config: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return config, fmt.Errorf("inspect opened controller config: %w", err)
	}
	if !safeConfigFile(openedInfo) || !os.SameFile(info, openedInfo) {
		return config, errors.New("controller config changed or became unsafe while opening")
	}

	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return config, fmt.Errorf("read controller config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return config, errors.New("controller config is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode controller config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Config{}, errors.New("controller config must contain exactly one JSON object")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Validate rejects unsafe listener and credential configurations.
func (c Config) Validate() error {
	ip, err := netip.ParseAddr(c.ServerIP)
	if err != nil || !ip.Is4() || ip.Zone() != "" || (!ip.IsGlobalUnicast() && !ip.IsLoopback()) {
		return errors.New("server_ip must be a unicast IPv4 address")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("tls_cert_file and tls_key_file must both be set")
	}
	if c.TLSCertFile == "" && !ip.IsLoopback() {
		return errors.New("TLS is required unless listening on loopback")
	}
	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir || c.StateDir == string(filepath.Separator) {
		return errors.New("state_dir must be a clean absolute non-root path")
	}
	if !validBearerToken(c.AdminToken) {
		return errors.New("admin_token must be 32 to 512 non-whitespace ASCII characters")
	}
	if len(c.Nodes) == 0 {
		return errors.New("at least one node credential is required")
	}
	ids := make(map[string]struct{}, len(c.Nodes))
	tokens := make(map[[32]byte]struct{}, len(c.Nodes))
	adminHash := sha256.Sum256([]byte(c.AdminToken))
	for _, node := range c.Nodes {
		if !validNodeID(node.ID) {
			return fmt.Errorf("invalid node ID %q", node.ID)
		}
		if !validBearerToken(node.Token) {
			return fmt.Errorf("node %q token must be 32 to 512 non-whitespace ASCII characters", node.ID)
		}
		if _, exists := ids[node.ID]; exists {
			return fmt.Errorf("duplicate node ID %q", node.ID)
		}
		ids[node.ID] = struct{}{}
		hash := sha256.Sum256([]byte(node.Token))
		if hash == adminHash {
			return errors.New("admin token must differ from node tokens")
		}
		if _, exists := tokens[hash]; exists {
			return errors.New("node tokens must be unique")
		}
		tokens[hash] = struct{}{}
	}
	if pxe := c.RuntimePXE(); pxe != nil {
		if err := pxe.Validate(c.Nodes); err != nil {
			return err
		}
	}
	return nil
}

func validBearerToken(token string) bool {
	if len(token) < 32 || len(token) > 512 {
		return false
	}
	for _, ch := range token {
		if ch < '!' || ch > '~' {
			return false
		}
	}
	return true
}

func safeConfigFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o007 == 0 && info.Mode().Perm()&0o020 == 0
}
