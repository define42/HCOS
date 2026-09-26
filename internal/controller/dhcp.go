package controller

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DHCPConfig configures a static, direct-attached IPv4 DHCP service. It must
// run only on an isolated provisioning interface, never on a production LAN.
type DHCPConfig struct {
	ListenAddress string      `json:"-"`
	Interface     string      `json:"interface"`
	ServerIP      string      `json:"-"`
	NextServerIP  string      `json:"-"`
	SubnetMask    string      `json:"subnet_mask"`
	Router        string      `json:"router,omitempty"`
	DNS           []string    `json:"dns,omitempty"`
	LeaseSeconds  uint32      `json:"lease_seconds,omitempty"`
	BootFile      string      `json:"boot_file,omitempty"`
	IPXEBootFile  string      `json:"ipxe_boot_file,omitempty"`
	Leases        []DHCPLease `json:"leases"`
}

// DHCPLease grants a single, pre-authorized machine a fixed IPv4 address.
type DHCPLease struct {
	NodeID       string `json:"node_id"`
	MAC          string `json:"mac"`
	IP           string `json:"ip"`
	BootFile     string `json:"boot_file,omitempty"`
	IPXEBootFile string `json:"ipxe_boot_file,omitempty"`
}

// DHCPServer responds to known, directly connected clients only. Its packet
// handling is independent of the UDP socket so malformed packets can be tested
// without binding privileged DHCP ports.
type DHCPServer struct {
	config       DHCPConfig
	serverIP     [4]byte
	nextServerIP [4]byte
	subnetMask   [4]byte
	router       [4]byte
	dns          [][4]byte
	leases       map[[6]byte]dhcpLease
	conn         *net.UDPConn
	closeOnce    sync.Once
}

type dhcpLease struct {
	nodeID       string
	ip           [4]byte
	bootFile     string
	ipxeBootFile string
}

// DHCPReply is the wire response and its UDP destination. DHCPNAK and
// first-lease replies are broadcast; renewals can be sent to ciaddr.
type DHCPReply struct {
	Packet      []byte
	Destination *net.UDPAddr
	NodeID      string
}

const (
	dhcpServerPort = 67
	dhcpClientPort = 68
	dhcpMinPacket  = 240
	dhcpMaxPacket  = 4096
	dhcpOffer      = 2
	dhcpAck        = 5
	dhcpNak        = 6
)

var dhcpCookie = [4]byte{99, 130, 83, 99}

// Validate checks the static DHCP scope without opening a socket.
func (config DHCPConfig) Validate() error {
	_, err := NewDHCPServer(config)
	return err
}

// NewDHCPServer validates the DHCP scope and prepares its static lease table.
// Call ListenDHCP to bind its socket before serving traffic.
func NewDHCPServer(config DHCPConfig) (*DHCPServer, error) {
	if config.ListenAddress == "" {
		config.ListenAddress = "0.0.0.0:67"
	}
	host, port, err := net.SplitHostPort(config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("dhcp listen_address: %w", err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("dhcp listen_address requires a UDP port from 1 to 65535")
	}
	if config.Interface == "" || len(config.Interface) > 15 || strings.ContainsAny(config.Interface, "\x00/ \\:\t\n") {
		return nil, errors.New("dhcp interface must be a Linux interface name")
	}
	serverIP, err := dhcpIPv4(config.ServerIP)
	if err != nil {
		return nil, fmt.Errorf("dhcp server_ip: %w", err)
	}
	if host != "0.0.0.0" && host != config.ServerIP {
		return nil, errors.New("dhcp listen_address must bind 0.0.0.0 or server_ip")
	}
	if config.NextServerIP == "" {
		config.NextServerIP = config.ServerIP
	}
	nextServerIP, err := dhcpIPv4(config.NextServerIP)
	if err != nil {
		return nil, fmt.Errorf("dhcp next_server_ip: %w", err)
	}
	maskIP := net.ParseIP(config.SubnetMask).To4()
	if maskIP == nil {
		return nil, errors.New("dhcp subnet_mask must be an IPv4 mask")
	}
	mask := net.IPMask(maskIP)
	ones, bits := mask.Size()
	if bits != 32 || ones < 1 || ones > 30 {
		return nil, errors.New("dhcp subnet_mask must be a contiguous IPv4 mask with usable host addresses")
	}
	var subnetMask [4]byte
	copy(subnetMask[:], maskIP)
	if !dhcpUsableInSubnet(serverIP, serverIP, subnetMask) {
		return nil, errors.New("dhcp server_ip is the network or broadcast address")
	}
	if !dhcpUsableInSubnet(nextServerIP, serverIP, subnetMask) {
		return nil, errors.New("dhcp next_server_ip must be a usable address in the DHCP subnet")
	}
	var router [4]byte
	if config.Router != "" {
		router, err = dhcpIPv4(config.Router)
		if err != nil || !dhcpUsableInSubnet(router, serverIP, subnetMask) {
			return nil, errors.New("dhcp router must be a usable address in the DHCP subnet")
		}
	}
	if len(config.DNS) > 4 {
		return nil, errors.New("dhcp dns supports at most four IPv4 servers")
	}
	dns := make([][4]byte, 0, len(config.DNS))
	for _, value := range config.DNS {
		ip, err := dhcpIPv4(value)
		if err != nil {
			return nil, fmt.Errorf("dhcp dns: %w", err)
		}
		dns = append(dns, ip)
	}
	if config.LeaseSeconds == 0 {
		config.LeaseSeconds = 3600
	}
	if config.LeaseSeconds < 60 || config.LeaseSeconds > 7*24*3600 {
		return nil, errors.New("dhcp lease_seconds must be between 60 and 604800")
	}
	if config.BootFile == "" {
		config.BootFile = "bootx64.efi"
	}
	if err := dhcpBootFile(config.BootFile, false); err != nil {
		return nil, fmt.Errorf("dhcp boot_file: %w", err)
	}
	if config.IPXEBootFile != "" {
		if err := dhcpBootFile(config.IPXEBootFile, true); err != nil {
			return nil, fmt.Errorf("dhcp ipxe_boot_file: %w", err)
		}
	}
	if len(config.Leases) == 0 {
		return nil, errors.New("dhcp requires at least one static lease")
	}
	leases := make(map[[6]byte]dhcpLease, len(config.Leases))
	leaseIPs := make(map[[4]byte]struct{}, len(config.Leases))
	nodeIDs := make(map[string]struct{}, len(config.Leases))
	for _, lease := range config.Leases {
		if !validNodeID(lease.NodeID) {
			return nil, fmt.Errorf("dhcp invalid node_id %q", lease.NodeID)
		}
		if _, ok := nodeIDs[lease.NodeID]; ok {
			return nil, fmt.Errorf("dhcp duplicate node_id %q", lease.NodeID)
		}
		mac, err := net.ParseMAC(lease.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			return nil, fmt.Errorf("dhcp node %q requires a unicast 6-byte MAC", lease.NodeID)
		}
		var macKey [6]byte
		copy(macKey[:], mac)
		if _, ok := leases[macKey]; ok {
			return nil, fmt.Errorf("dhcp duplicate MAC %s", lease.MAC)
		}
		ip, err := dhcpIPv4(lease.IP)
		if err != nil || !dhcpUsableInSubnet(ip, serverIP, subnetMask) || ip == serverIP || ip == nextServerIP || (router != [4]byte{} && ip == router) {
			return nil, fmt.Errorf("dhcp node %q IP must be an unused host address in the DHCP subnet", lease.NodeID)
		}
		if _, ok := leaseIPs[ip]; ok {
			return nil, fmt.Errorf("dhcp duplicate lease IP %s", lease.IP)
		}
		bootFile := lease.BootFile
		if bootFile == "" {
			bootFile = config.BootFile
		}
		if err := dhcpBootFile(bootFile, false); err != nil {
			return nil, fmt.Errorf("dhcp node %q boot_file: %w", lease.NodeID, err)
		}
		ipxeBootFile := lease.IPXEBootFile
		if ipxeBootFile == "" {
			ipxeBootFile = config.IPXEBootFile
		}
		if ipxeBootFile != "" {
			if err := dhcpBootFile(ipxeBootFile, true); err != nil {
				return nil, fmt.Errorf("dhcp node %q ipxe_boot_file: %w", lease.NodeID, err)
			}
		}
		leases[macKey] = dhcpLease{nodeID: lease.NodeID, ip: ip, bootFile: bootFile, ipxeBootFile: ipxeBootFile}
		leaseIPs[ip] = struct{}{}
		nodeIDs[lease.NodeID] = struct{}{}
	}
	return &DHCPServer{config: config, serverIP: serverIP, nextServerIP: nextServerIP, subnetMask: subnetMask, router: router, dns: dns, leases: leases}, nil
}

func dhcpIPv4(value string) ([4]byte, error) {
	var result [4]byte
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() || (!addr.IsGlobalUnicast() && !addr.IsLoopback()) {
		return result, errors.New("must be a unicast IPv4 address")
	}
	return addr.As4(), nil
}

func dhcpUsableInSubnet(ip, server, mask [4]byte) bool {
	allHostZero, allHostOne := true, true
	for i := range ip {
		if ip[i]&mask[i] != server[i]&mask[i] {
			return false
		}
		host := ip[i] &^ mask[i]
		if host != 0 {
			allHostZero = false
		}
		if host != ^mask[i] {
			allHostOne = false
		}
	}
	return !allHostZero && !allHostOne
}

func dhcpBootFile(value string, httpURL bool) error {
	if value == "" || len(value) > 127 || strings.ContainsAny(value, "\x00\r\n\\") {
		return errors.New("must be 1 to 127 bytes without control characters or backslashes")
	}
	for _, ch := range value {
		if ch < 0x21 || ch > 0x7e {
			return errors.New("must contain printable ASCII without spaces")
		}
	}
	if httpURL {
		if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			return errors.New("must be an HTTP or HTTPS URL")
		}
		parsed, err := neturlParse(value)
		if err != nil || parsed == "" {
			return errors.New("must be an absolute HTTP or HTTPS URL without credentials or a fragment")
		}
		return nil
	}
	if strings.HasPrefix(value, "/") || strings.Contains(value, "..") || strings.Contains(value, ":") {
		return errors.New("must be a relative TFTP path without traversal")
	}
	return nil
}

// neturlParse keeps URL acceptance narrow enough for DHCP option 67.
func neturlParse(value string) (string, error) {
	parsed, err := neturl.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", errors.New("invalid boot URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("invalid boot URL scheme")
	}
	return parsed.Hostname(), nil
}

type dhcpRequest struct {
	packet       []byte
	messageType  byte
	clientIP     [4]byte
	requestedIP  [4]byte
	hasRequested bool
	serverID     [4]byte
	hasServerID  bool
	mac          [6]byte
	broadcast    bool
	arch         []byte
	isIPXE       bool
}

func parseDHCPRequest(packet []byte) (dhcpRequest, bool) {
	var request dhcpRequest
	if len(packet) < dhcpMinPacket || len(packet) > dhcpMaxPacket || packet[0] != 1 || packet[1] != 1 || packet[2] != 6 || packet[3] != 0 || !bytes.Equal(packet[236:240], dhcpCookie[:]) {
		return request, false
	}
	// Relayed traffic is outside this one-interface, one-subnet server's scope.
	if packet[24] != 0 || packet[25] != 0 || packet[26] != 0 || packet[27] != 0 {
		return request, false
	}
	request.packet = packet
	copy(request.mac[:], packet[28:34])
	copy(request.clientIP[:], packet[12:16])
	request.broadcast = packet[10]&0x80 != 0
	options, ok := parseDHCPOptions(packet[240:])
	if !ok || len(options[53]) != 1 {
		return dhcpRequest{}, false
	}
	request.messageType = options[53][0]
	if requested, exists := options[50]; exists {
		if len(requested) != 4 {
			return dhcpRequest{}, false
		}
		copy(request.requestedIP[:], requested)
		request.hasRequested = true
	}
	if serverID, exists := options[54]; exists {
		if len(serverID) != 4 {
			return dhcpRequest{}, false
		}
		copy(request.serverID[:], serverID)
		request.hasServerID = true
	}
	if architecture, exists := options[93]; exists {
		if len(architecture) == 0 || len(architecture)%2 != 0 {
			return dhcpRequest{}, false
		}
		request.arch = architecture
	}
	_, request.isIPXE = options[175]
	if vendorClass, exists := options[60]; exists && bytes.HasPrefix(vendorClass, []byte("iPXE")) {
		request.isIPXE = true
	}
	return request, true
}

func parseDHCPOptions(data []byte) (map[byte][]byte, bool) {
	result := make(map[byte][]byte)
	for offset := 0; offset < len(data); {
		code := data[offset]
		offset++
		if code == 0 {
			continue
		}
		if code == 255 {
			return result, true
		}
		if offset >= len(data) {
			return nil, false
		}
		length := int(data[offset])
		offset++
		if length > len(data)-offset {
			return nil, false
		}
		// Critical option duplicates create ambiguous state; ignore the packet.
		if _, exists := result[code]; exists && (code == 53 || code == 50 || code == 54 || code == 93) {
			return nil, false
		}
		result[code] = data[offset : offset+length]
		offset += length
	}
	return nil, false
}

func hasUEFIX64Architecture(arch []byte) bool {
	for offset := 0; offset+1 < len(arch); offset += 2 {
		value := binary.BigEndian.Uint16(arch[offset:])
		if value == 7 || value == 9 {
			return true
		}
	}
	return false
}

// HandlePacket returns no response for unknown MACs, relay traffic, malformed
// packets, and clients selecting another DHCP server.
func (server *DHCPServer) HandlePacket(packet []byte) (DHCPReply, bool) {
	request, ok := parseDHCPRequest(packet)
	if !ok {
		return DHCPReply{}, false
	}
	lease, ok := server.leases[request.mac]
	if !ok {
		return DHCPReply{}, false
	}
	messageType := byte(0)
	switch request.messageType {
	case 1: // DHCPDISCOVER
		messageType = dhcpOffer
	case 3: // DHCPREQUEST
		if request.hasServerID && request.serverID != server.serverIP {
			return DHCPReply{}, false
		}
		if request.hasServerID && !request.hasRequested {
			return DHCPReply{}, false
		}
		if request.hasRequested && request.clientIP != [4]byte{} {
			return DHCPReply{}, false
		}
		requestedIP := request.clientIP
		if request.hasRequested {
			requestedIP = request.requestedIP
		}
		if requestedIP == [4]byte{} {
			return DHCPReply{}, false
		}
		if requestedIP == lease.ip {
			messageType = dhcpAck
		} else {
			messageType = dhcpNak
		}
	default:
		return DHCPReply{}, false
	}
	response := make([]byte, dhcpMinPacket, 576)
	response[0], response[1], response[2] = 2, 1, 6
	copy(response[4:8], packet[4:8])     // xid
	copy(response[10:12], packet[10:12]) // flags
	copy(response[28:44], packet[28:44])
	copy(response[236:240], dhcpCookie[:])
	if messageType != dhcpNak {
		if messageType == dhcpAck {
			copy(response[12:16], request.clientIP[:])
		}
		copy(response[16:20], lease.ip[:])
		copy(response[20:24], server.nextServerIP[:])
		bootFile := ""
		if request.isIPXE {
			bootFile = lease.ipxeBootFile
		} else if hasUEFIX64Architecture(request.arch) {
			bootFile = lease.bootFile
		}
		if bootFile != "" {
			copy(response[108:236], bootFile)
			response = appendDHCPOption(response, 67, []byte(bootFile))
		}
	}
	response = appendDHCPOption(response, 53, []byte{messageType})
	response = appendDHCPOption(response, 54, server.serverIP[:])
	if messageType == dhcpNak {
		response = appendDHCPOption(response, 56, []byte("address not assigned to this MAC"))
	} else {
		response = appendDHCPOption(response, 1, server.subnetMask[:])
		response = appendDHCPOption(response, 51, binary.BigEndian.AppendUint32(nil, server.config.LeaseSeconds))
		if server.router != [4]byte{} {
			response = appendDHCPOption(response, 3, server.router[:])
		}
		if len(server.dns) != 0 {
			data := make([]byte, 0, len(server.dns)*4)
			for _, ip := range server.dns {
				data = append(data, ip[:]...)
			}
			response = appendDHCPOption(response, 6, data)
		}
		if hasUEFIX64Architecture(request.arch) && !request.isIPXE {
			response = appendDHCPOption(response, 66, []byte(server.config.NextServerIP))
		}
	}
	response = append(response, 255)
	if len(response) < 300 {
		response = append(response, make([]byte, 300-len(response))...)
	}
	destination := &net.UDPAddr{Port: dhcpClientPort}
	if messageType == dhcpNak || request.broadcast {
		destination.IP = net.IPv4bcast
	} else if request.clientIP != [4]byte{} {
		destination.IP = net.IP(request.clientIP[:])
	} else {
		// A UDP socket cannot address the link-layer MAC explicitly. Broadcast
		// the initial reply so an unconfigured PXE stack can receive it.
		destination.IP = net.IPv4bcast
	}
	return DHCPReply{Packet: response, Destination: destination, NodeID: lease.nodeID}, true
}

func appendDHCPOption(packet []byte, code byte, value []byte) []byte {
	return append(append(packet, code, byte(len(value))), value...)
}

// Serve processes UDP packets until the context is cancelled or the socket is
// closed. ListenDHCP must be called first.
func (server *DHCPServer) Serve(ctx context.Context) error {
	if server.conn == nil {
		return errors.New("dhcp socket is not bound; call ListenDHCP")
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	defer close(done)
	packet := make([]byte, dhcpMaxPacket+1)
	for {
		_ = server.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, _, err := server.conn.ReadFromUDP(packet)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return fmt.Errorf("read DHCP packet: %w", err)
		}
		reply, ok := server.HandlePacket(packet[:n])
		if !ok {
			continue
		}
		if _, err := server.conn.WriteToUDP(reply.Packet, reply.Destination); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("send DHCP reply: %w", err)
		}
	}
}

// Close releases the bound UDP socket. It is safe to call more than once.
func (server *DHCPServer) Close() error {
	var err error
	server.closeOnce.Do(func() {
		if server.conn != nil {
			err = server.conn.Close()
		}
	})
	return err
}
