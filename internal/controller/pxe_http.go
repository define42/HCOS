package controller

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// PXEConfig enables the isolated, IPv4-only fallback for UEFI PXE machines.
// DHCP and TFTP deliver a small iPXE loader; HTTP serves its script and proxies
// the personalized EFI from the existing boot server. Boot tokens stay server-side.
type PXEConfig struct {
	HTTPListenAddress string            `json:"http_listen_address"`
	BootServerURL     string            `json:"boot_server_url"`
	BootCAFile        string            `json:"boot_ca_file,omitempty"`
	DHCP              DHCPConfig        `json:"dhcp"`
	TFTP              TFTPConfig        `json:"tftp"`
	BootTokens        map[string]string `json:"boot_tokens"`
}

// Validate keeps the fallback bound to one explicit provisioning IPv4 address.
func (p PXEConfig) Validate(nodes []NodeCredential) error {
	if err := p.DHCP.Validate(); err != nil {
		return fmt.Errorf("pxe.dhcp: %w", err)
	}
	if err := p.TFTP.Validate(); err != nil {
		return fmt.Errorf("pxe.tftp: %w", err)
	}
	address, err := netip.ParseAddrPort(p.HTTPListenAddress)
	if err != nil || !address.Addr().Is4() || address.Addr().IsUnspecified() || address.Port() == 0 {
		return errors.New("pxe.http_listen_address must be a specific IPv4 address and port")
	}
	serverIP, err := netip.ParseAddr(p.DHCP.ServerIP)
	if err != nil || address.Addr() != serverIP {
		return errors.New("PXE HTTP must listen on pxe.dhcp.server_ip")
	}
	if !serverIP.IsLoopback() && address.Port() != 80 {
		return errors.New("PXE HTTP must use port 80 for the embedded iPXE loader")
	}
	tftpAddress, err := netip.ParseAddrPort(p.TFTP.ListenAddress)
	if err != nil || tftpAddress.Addr() != serverIP {
		return errors.New("PXE TFTP must listen on pxe.dhcp.server_ip")
	}
	if !serverIP.IsLoopback() && tftpAddress.Port() != 69 {
		return errors.New("PXE TFTP must use port 69 for firmware PXE clients")
	}
	if p.DHCP.NextServerIP != "" && p.DHCP.NextServerIP != p.DHCP.ServerIP {
		return errors.New("PXE next_server_ip must point to this TFTP server")
	}
	if p.DHCP.BootFile != "" && p.DHCP.BootFile != "bootx64.efi" {
		return errors.New("PXE boot_file must be bootx64.efi")
	}
	expectedScript := pxeScriptURL(p.HTTPListenAddress)
	if p.DHCP.IPXEBootFile != "" && p.DHCP.IPXEBootFile != expectedScript {
		return errors.New("PXE ipxe_boot_file must point to this controller's boot script")
	}
	for _, lease := range p.DHCP.Leases {
		if lease.BootFile != "" && lease.BootFile != "bootx64.efi" {
			return fmt.Errorf("PXE node %q boot_file must be bootx64.efi", lease.NodeID)
		}
		if lease.IPXEBootFile != "" && lease.IPXEBootFile != expectedScript {
			return fmt.Errorf("PXE node %q iPXE URL must point to this controller", lease.NodeID)
		}
	}
	bootURL, err := parseBootServerURL(p.BootServerURL)
	if err != nil {
		return fmt.Errorf("pxe.boot_server_url: %w", err)
	}
	if bootURL.Scheme == "https" {
		if !filepath.IsAbs(p.BootCAFile) {
			return errors.New("pxe.boot_ca_file must be an absolute CA path for HTTPS")
		}
	} else if p.BootCAFile != "" {
		return errors.New("pxe.boot_ca_file is only used with HTTPS")
	}
	ids := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		ids[node.ID] = true
	}
	if len(p.DHCP.Leases) == 0 || len(p.BootTokens) != len(p.DHCP.Leases) {
		return errors.New("PXE requires one boot token for each static DHCP lease")
	}
	for _, lease := range p.DHCP.Leases {
		if !ids[lease.NodeID] {
			return fmt.Errorf("PXE lease references unknown controller node %q", lease.NodeID)
		}
		if !validBearerToken(p.BootTokens[lease.NodeID]) {
			return fmt.Errorf("PXE node %q needs a 32-512 character boot token", lease.NodeID)
		}
		for _, node := range nodes {
			if node.ID == lease.NodeID && node.Token == p.BootTokens[lease.NodeID] {
				return fmt.Errorf("PXE node %q must use a distinct boot token", lease.NodeID)
			}
		}
	}
	return nil
}

func parseBootServerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("must be an HTTP(S) origin without path, query, or credentials")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	if u.Scheme != "http" {
		return nil, errors.New("must use HTTPS, except for loopback HTTP")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("HTTP boot server must be on loopback")
	}
	return u, nil
}

type pxeNode struct {
	id    string
	token string
}

type pxeHandler struct {
	baseURL *url.URL
	client  *http.Client
	byIP    map[netip.Addr]pxeNode
	script  []byte
}

// NewPXEHandler serves only the iPXE script and each allowlisted node's EFI.
// Access is based on the source IP of a static lease; run this on an isolated
// provisioning network, since PXE/TFTP/HTTP provide no client authentication.
func NewPXEHandler(config PXEConfig) (http.Handler, error) {
	baseURL, err := parseBootServerURL(config.BootServerURL)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if baseURL.Scheme == "https" {
		certificate, err := os.ReadFile(config.BootCAFile)
		if err != nil {
			return nil, fmt.Errorf("read boot server CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			return nil, errors.New("PXE boot server CA contains no PEM certificates")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	}
	byIP := make(map[netip.Addr]pxeNode, len(config.DHCP.Leases))
	for _, lease := range config.DHCP.Leases {
		ip, err := netip.ParseAddr(lease.IP)
		if err != nil || !ip.Is4() || !validNodeID(lease.NodeID) || config.BootTokens[lease.NodeID] == "" {
			return nil, errors.New("invalid PXE node lease or boot token")
		}
		if _, duplicate := byIP[ip]; duplicate {
			return nil, errors.New("duplicate PXE node IP")
		}
		byIP[ip] = pxeNode{id: lease.NodeID, token: config.BootTokens[lease.NodeID]}
	}
	address, err := netip.ParseAddrPort(config.HTTPListenAddress)
	if err != nil {
		return nil, err
	}
	origin := "http://" + address.Addr().String()
	if address.Port() != 80 {
		origin += ":" + strconv.Itoa(int(address.Port()))
	}
	h := &pxeHandler{
		baseURL: baseURL,
		client: &http.Client{Transport: transport, Timeout: 10 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		byIP:   byIP,
		script: []byte("#!ipxe\nchain " + origin + "/boot/hcos.efi\n"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boot/boot.ipxe", h.serveScript)
	mux.HandleFunc("GET /boot/hcos.efi", h.serveEFI)
	mux.HandleFunc("HEAD /boot/hcos.efi", h.serveEFI)
	return mux, nil
}

func (h *pxeHandler) nodeForRequest(r *http.Request) (pxeNode, bool) {
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return pxeNode{}, false
	}
	ip, err := netip.ParseAddr(remote)
	if err != nil {
		return pxeNode{}, false
	}
	node, found := h.byIP[ip.Unmap()]
	return node, found
}

func (h *pxeHandler) serveScript(w http.ResponseWriter, r *http.Request) {
	if _, found := h.nodeForRequest(r); !found || r.URL.RawQuery != "" {
		http.Error(w, "unknown PXE client", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(h.script)))
	_, _ = w.Write(h.script)
}

func (h *pxeHandler) serveEFI(w http.ResponseWriter, r *http.Request) {
	node, found := h.nodeForRequest(r)
	if !found || r.URL.RawQuery != "" {
		http.Error(w, "unknown PXE client", http.StatusForbidden)
		return
	}
	upstream := *h.baseURL
	upstream.Path = "/boot/hcos.efi"
	query := url.Values{"node": {node.id}, "token": {node.token}}
	upstream.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(r.Context(), r.Method, upstream.String(), nil)
	if err != nil {
		http.Error(w, "boot request failed", http.StatusBadGateway)
		return
	}
	response, err := h.client.Do(request)
	if err != nil {
		// net/http errors often include the requested URL, which contains the
		// boot token. Never send the error text to logs.
		slog.Warn("PXE boot fetch failed", "node", node.id)
		http.Error(w, "boot image unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength <= 0 || response.ContentLength > 2<<30 {
		slog.Warn("PXE boot server returned unusable image", "node", node.id, "status", response.StatusCode)
		http.Error(w, "boot image unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	written, err := io.Copy(w, io.LimitReader(response.Body, response.ContentLength))
	if err != nil || written != response.ContentLength {
		slog.Warn("PXE EFI transfer incomplete", "node", node.id, "bytes", written)
		return
	}
	slog.Info("PXE EFI delivered", "node", node.id, "bytes", written)
}

// PXEHTTPServer gives large EFI downloads time to complete without unbounded
// reads from boot clients. It is deliberately separate from the TLS admin API.
func PXEHTTPServer(config PXEConfig, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              config.HTTPListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

func pxeScriptURL(address string) string {
	return "http://" + address + "/boot/boot.ipxe"
}
