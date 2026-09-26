package bootserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/define42/HCOS/internal/protocol"
)

// Config contains only local inputs. No boot request causes an outbound request.
type Config struct {
	Listen    string         `json:"listen"`
	PXEHTTP   bool           `json:"pxe_http,omitempty"`
	TLSCert   string         `json:"tls_cert,omitempty"`
	TLSKey    string         `json:"tls_key,omitempty"`
	ImagesDir string         `json:"images_dir"`
	AgentsDir string         `json:"agents_dir"`
	TrustDir  string         `json:"trust_dir"`
	CacheDir  string         `json:"cache_dir"`
	NodesFile string         `json:"nodes_file"`
	Signing   *SigningConfig `json:"signing,omitempty"`
}

type SigningConfig struct {
	Command     string `json:"command"`
	Key         string `json:"key"`
	Certificate string `json:"certificate"`
	Revision    string `json:"revision"`
}

type Node struct {
	ID           string               `json:"id"`
	BootToken    string               `json:"boot_token"`
	HCOSVersion  string               `json:"hcos_version"`
	AgentVersion string               `json:"agent_version"`
	CAVersion    string               `json:"ca_version"`
	HCOSSHA256   string               `json:"hcos_sha256,omitempty"`
	AgentSHA256  string               `json:"agent_sha256,omitempty"`
	CASHA256     string               `json:"ca_sha256,omitempty"`
	Config       protocol.AgentConfig `json:"config"`
}

type nodeFile struct {
	Nodes []Node `json:"nodes"`
}

var versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var nodeIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func LoadConfig(path string) (Config, error) {
	var config Config
	if err := readJSON(path, &config); err != nil {
		return config, fmt.Errorf("read server configuration: %w", err)
	}
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key must be set together")
	}
	if c.TLSCert != "" && (!filepath.IsAbs(c.TLSCert) || !filepath.IsAbs(c.TLSKey)) {
		return errors.New("tls_cert and tls_key must be absolute paths")
	}
	if c.TLSCert == "" {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil || host == "" || !isLoopback(host) {
			return errors.New("TLS is required except when listening on loopback")
		}
	}
	if c.PXEHTTP {
		if c.TLSCert == "" {
			return errors.New("pxe_http requires TLS on the main listener")
		}
		host, port, err := net.SplitHostPort(c.Listen)
		if err != nil {
			return errors.New("pxe_http requires listen to contain an IPv4 address and port")
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() ||
			ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return errors.New("pxe_http requires a specific unicast IPv4 listen address")
		}
		if port == "80" {
			return errors.New("pxe_http reserves port 80; use a different port for the TLS listener")
		}
	}
	for name, path := range map[string]string{
		"images_dir": c.ImagesDir, "agents_dir": c.AgentsDir,
		"trust_dir": c.TrustDir, "cache_dir": c.CacheDir,
		"nodes_file": c.NodesFile,
	} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	if c.Signing != nil {
		if c.Signing.Revision == "" {
			return errors.New("signing.revision is required")
		}
		for name, path := range map[string]string{
			"signing.command":     c.Signing.Command,
			"signing.key":         c.Signing.Key,
			"signing.certificate": c.Signing.Certificate,
		} {
			if !filepath.IsAbs(path) {
				return fmt.Errorf("%s must be an absolute path", name)
			}
		}
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func loadNodes(path string) (map[string]Node, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 || info.Mode().Perm()&0o020 != 0 {
		return nil, errors.New("nodes_file must be a regular file without public access or group write permission")
	}
	var data nodeFile
	if err := readJSON(path, &data); err != nil {
		return nil, fmt.Errorf("read node configuration: %w", err)
	}
	if len(data.Nodes) == 0 {
		return nil, errors.New("node configuration contains no nodes")
	}
	nodes := make(map[string]Node, len(data.Nodes))
	for _, node := range data.Nodes {
		if err := node.validate(); err != nil {
			return nil, fmt.Errorf("node %q: %w", node.ID, err)
		}
		if _, found := nodes[node.ID]; found {
			return nil, fmt.Errorf("duplicate node %q", node.ID)
		}
		nodes[node.ID] = node
	}
	return nodes, nil
}

func (n Node) validate() error {
	if !nodeIDRE.MatchString(n.ID) || n.Config.NodeID != n.ID {
		return errors.New("id must match config.node_id and contain only safe characters")
	}
	if len(n.BootToken) < 32 {
		return errors.New("boot_token must contain at least 32 characters")
	}
	for name, version := range map[string]string{
		"hcos_version":  n.HCOSVersion,
		"agent_version": n.AgentVersion,
		"ca_version":    n.CAVersion,
	} {
		if !versionRE.MatchString(version) || version == "." || version == ".." {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if n.Config.APIVersion != protocol.APIVersion {
		return fmt.Errorf("config.api_version must be %q", protocol.APIVersion)
	}
	if n.Config.Hostname == "" || n.Config.Controller == "" || n.Config.ControllerToken == "" {
		return errors.New("config.hostname, controller and controller_token are required")
	}
	if n.Config.Storage.Path != "" && !filepath.IsAbs(n.Config.Storage.Path) {
		return errors.New("config.storage.path must be absolute when set")
	}
	if n.Config.Network.ManagementInterface == "" || n.Config.Network.VMBridge == "" {
		return errors.New("config.network interface and bridge are required")
	}
	return nil
}

func readJSON(path string, destination any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return errors.New("JSON file exceeds 4 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("JSON file must contain exactly one value")
}
