package controller

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func testDHCPConfig() DHCPConfig {
	return DHCPConfig{
		ListenAddress: "0.0.0.0:1067",
		Interface:     "pxe0",
		ServerIP:      "192.0.2.1",
		SubnetMask:    "255.255.255.0",
		Router:        "192.0.2.1",
		DNS:           []string{"192.0.2.53"},
		BootFile:      "bootx64.efi",
		IPXEBootFile:  tftpScriptURL("192.0.2.1"),
		Leases: []DHCPLease{{
			NodeID: "compute-01", MAC: "52:54:00:12:34:56", IP: "192.0.2.100",
		}},
	}
}

func testDHCPRequest(message byte, extraOptions ...byte) []byte {
	packet := make([]byte, dhcpMinPacket)
	packet[0], packet[1], packet[2] = 1, 1, 6
	copy(packet[4:8], []byte{0x12, 0x34, 0x56, 0x78})
	copy(packet[28:34], []byte{0x52, 0x54, 0, 0x12, 0x34, 0x56})
	copy(packet[236:240], dhcpCookie[:])
	packet = append(packet, 53, 1, message)
	packet = append(packet, extraOptions...)
	return append(packet, 255)
}

func testDHCPOptions(t *testing.T, packet []byte) map[byte][]byte {
	t.Helper()
	options, valid := parseDHCPOptions(packet[240:])
	if !valid {
		t.Fatal("server emitted invalid DHCP options")
	}
	return options
}

func TestDHCPUEFIPXEOfferAndRequest(t *testing.T) {
	server, err := NewDHCPServer(testDHCPConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Architecture 9 is EFI x86-64; 7 (EFI BC) is also accepted below.
	discover := testDHCPRequest(1, 93, 2, 0, 9)
	discover[10] = 0x80 // Client requests broadcast replies.
	offer, ok := server.HandlePacket(discover)
	if !ok {
		t.Fatal("expected a static-lease offer")
	}
	if offer.NodeID != "compute-01" || !offer.Destination.IP.Equal(net.IPv4bcast) || offer.Destination.Port != 68 {
		t.Fatalf("incorrect offer destination or identity: %+v", offer)
	}
	if !bytes.Equal(offer.Packet[4:8], discover[4:8]) || !bytes.Equal(offer.Packet[16:20], net.IPv4(192, 0, 2, 100).To4()) || !bytes.Equal(offer.Packet[20:24], net.IPv4(192, 0, 2, 1).To4()) {
		t.Fatal("offer did not preserve xid or set yiaddr/siaddr")
	}
	if got := string(bytes.TrimRight(offer.Packet[108:236], "\x00")); got != "bootx64.efi" {
		t.Fatalf("unexpected BOOTP file field %q", got)
	}
	options := testDHCPOptions(t, offer.Packet)
	if !bytes.Equal(options[53], []byte{dhcpOffer}) || string(options[67]) != "bootx64.efi" || !bytes.Equal(options[54], net.IPv4(192, 0, 2, 1).To4()) || !bytes.Equal(options[1], net.IPv4(255, 255, 255, 0).To4()) {
		t.Fatal("offer omitted required DHCP/PXE options")
	}
	if binary.BigEndian.Uint32(options[51]) != 3600 || !bytes.Equal(options[3], net.IPv4(192, 0, 2, 1).To4()) || !bytes.Equal(options[6], net.IPv4(192, 0, 2, 53).To4()) {
		t.Fatal("offer omitted lease, router, or DNS options")
	}
	if string(options[66]) != "192.0.2.1" {
		t.Fatalf("missing TFTP server option: %q", options[66])
	}
	request := testDHCPRequest(3, 50, 4, 192, 0, 2, 100, 54, 4, 192, 0, 2, 1, 93, 2, 0, 7)
	ack, ok := server.HandlePacket(request)
	if !ok || !bytes.Equal(testDHCPOptions(t, ack.Packet)[53], []byte{dhcpAck}) {
		t.Fatal("expected ACK for selected static IP")
	}
}

func TestDHCPIpXESecondStageDoesNotLoop(t *testing.T) {
	server, err := NewDHCPServer(testDHCPConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, nameAndOptions := range []struct {
		name    string
		options []byte
	}{
		{"ipxe-option", []byte{93, 2, 0, 9, 175, 0}},
		{"vendor-class", []byte{93, 2, 0, 9, 60, 4, 'i', 'P', 'X', 'E'}},
	} {
		t.Run(nameAndOptions.name, func(t *testing.T) {
			request := testDHCPRequest(1, nameAndOptions.options...)
			reply, ok := server.HandlePacket(request)
			if !ok {
				t.Fatal("expected DHCP reply for known iPXE machine")
			}
			got := string(testDHCPOptions(t, reply.Packet)[67])
			if got != "tftp://192.0.2.1/boot.ipxe" {
				t.Fatalf("iPXE should fetch TFTP script, got %q", got)
			}
		})
	}
	// Ordinary OS DHCP, without PXE architecture, receives the lease only.
	reply, ok := server.HandlePacket(testDHCPRequest(1))
	if !ok {
		t.Fatal("expected a lease for the known MAC")
	}
	if _, exists := testDHCPOptions(t, reply.Packet)[67]; exists {
		t.Fatal("non-PXE DHCP client was given a boot file")
	}
}

func TestDHCPRejectsWrongStaticAddressAndOtherServer(t *testing.T) {
	server, err := NewDHCPServer(testDHCPConfig())
	if err != nil {
		t.Fatal(err)
	}
	request := testDHCPRequest(3, 50, 4, 192, 0, 2, 101, 54, 4, 192, 0, 2, 1)
	reply, ok := server.HandlePacket(request)
	if !ok || !bytes.Equal(testDHCPOptions(t, reply.Packet)[53], []byte{dhcpNak}) || !reply.Destination.IP.Equal(net.IPv4bcast) {
		t.Fatal("expected broadcast NAK for wrong requested address")
	}
	if !bytes.Equal(reply.Packet[16:24], make([]byte, 8)) {
		t.Fatal("NAK must not offer an address or next bootstrap server")
	}
	otherServer := testDHCPRequest(3, 50, 4, 192, 0, 2, 100, 54, 4, 192, 0, 2, 2)
	if _, ok := server.HandlePacket(otherServer); ok {
		t.Fatal("responded to a client selecting another DHCP server")
	}
}

func TestDHCPRenewalUsesClientAddress(t *testing.T) {
	server, err := NewDHCPServer(testDHCPConfig())
	if err != nil {
		t.Fatal(err)
	}
	request := testDHCPRequest(3)
	copy(request[12:16], net.IPv4(192, 0, 2, 100).To4())
	reply, ok := server.HandlePacket(request)
	if !ok || !bytes.Equal(testDHCPOptions(t, reply.Packet)[53], []byte{dhcpAck}) {
		t.Fatal("expected ACK for static lease renewal")
	}
	if !reply.Destination.IP.Equal(net.IPv4(192, 0, 2, 100)) {
		t.Fatalf("renewal should be unicast to ciaddr, got %s", reply.Destination.IP)
	}
	if !bytes.Equal(reply.Packet[12:16], net.IPv4(192, 0, 2, 100).To4()) {
		t.Fatal("renewal ACK did not retain ciaddr")
	}
}

func TestDHCPUnknownOrMalformedPacketsAreIgnored(t *testing.T) {
	server, err := NewDHCPServer(testDHCPConfig())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		packet []byte
	}{
		{"unknown MAC", func() []byte { p := testDHCPRequest(1); p[33]++; return p }()},
		{"bad cookie", func() []byte { p := testDHCPRequest(1); p[236] = 0; return p }()},
		{"truncated option", append(testDHCPRequest(1)[:243:243], 93, 4, 0)},
		{"duplicate message type", testDHCPRequest(1, 53, 1, 3)},
		{"odd architecture list", testDHCPRequest(1, 93, 1, 9)},
		{"relayed client", func() []byte { p := testDHCPRequest(1); p[27] = 1; return p }()},
		{"missing end option", testDHCPRequest(1)[:243]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := server.HandlePacket(test.packet); ok {
				t.Fatal("unsafe packet produced a DHCP response")
			}
		})
	}
}

func TestDHCPConfigRejectsUnsafeScope(t *testing.T) {
	tests := []struct {
		name   string
		change func(*DHCPConfig)
	}{
		{"missing interface", func(c *DHCPConfig) { c.Interface = "" }},
		{"wrong listen IP", func(c *DHCPConfig) { c.ListenAddress = "192.0.2.99:67" }},
		{"bad subnet mask", func(c *DHCPConfig) { c.SubnetMask = "255.0.255.0" }},
		{"network address lease", func(c *DHCPConfig) { c.Leases[0].IP = "192.0.2.0" }},
		{"duplicate MAC", func(c *DHCPConfig) {
			c.Leases = append(c.Leases, DHCPLease{NodeID: "compute-02", MAC: c.Leases[0].MAC, IP: "192.0.2.101"})
		}},
		{"duplicate IP", func(c *DHCPConfig) {
			c.Leases = append(c.Leases, DHCPLease{NodeID: "compute-02", MAC: "52:54:00:12:34:57", IP: c.Leases[0].IP})
		}},
		{"duplicate node", func(c *DHCPConfig) {
			c.Leases = append(c.Leases, DHCPLease{NodeID: c.Leases[0].NodeID, MAC: "52:54:00:12:34:57", IP: "192.0.2.101"})
		}},
		{"TFTP traversal", func(c *DHCPConfig) { c.BootFile = "../bootx64.efi" }},
		{"unsupported iPXE URL scheme", func(c *DHCPConfig) { c.IPXEBootFile = "ftp://192.0.2.1/boot.ipxe" }},
		{"TFTP URL credentials", func(c *DHCPConfig) { c.IPXEBootFile = "tftp://user@192.0.2.1/boot.ipxe" }},
		{"TFTP URL fragment", func(c *DHCPConfig) { c.IPXEBootFile = "tftp://192.0.2.1/boot.ipxe#script" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testDHCPConfig()
			test.change(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("unsafe DHCP scope accepted")
			}
		})
	}
}
