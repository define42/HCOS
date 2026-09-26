package controller

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTFTPConfigAndAssetValidation(t *testing.T) {
	config := TFTPConfig{ListenAddress: "127.0.0.1:1069"}
	server, err := NewTFTPServer(config)
	if err != nil {
		t.Fatalf("embedded loader: %v", err)
	}
	if !bytes.HasPrefix(server.loader, []byte("MZ")) {
		t.Fatal("embedded iPXE loader is not a PE image")
	}
	bad := config
	bad.ListenAddress = "127.0.0.1:0"
	if _, err := NewTFTPServer(bad); err == nil {
		t.Fatal("zero listen port accepted")
	}
	bad = config
	bad.ScriptPath = "relative.ipxe"
	if _, err := NewTFTPServer(bad); err == nil {
		t.Fatal("relative script path accepted")
	}
	folder := t.TempDir()
	script := filepath.Join(folder, "boot.ipxe")
	if err := os.WriteFile(script, []byte("#!ipxe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad.ScriptPath = script
	if _, err := NewTFTPServer(bad); err != nil {
		t.Fatalf("valid script: %v", err)
	}
	symlink := filepath.Join(folder, "linked.ipxe")
	if err := os.Symlink(script, symlink); err != nil {
		t.Fatal(err)
	}
	bad.ScriptPath = symlink
	if _, err := NewTFTPServer(bad); err == nil {
		t.Fatal("symlinked script accepted")
	}
}

func TestTFTPServesEmbeddedIPXE(t *testing.T) {
	address := startTFTPTestServer(t, nil, nil)
	got := fetchTFTP(t, address, "bootx64.efi", 1024, false)
	if !bytes.Equal(got, embeddedIPXELoader) {
		t.Fatalf("embedded loader differs: got %d bytes, want %d", len(got), len(embeddedIPXELoader))
	}
}

func TestTFTPOctetTransferOptionsAndFinalEmptyBlock(t *testing.T) {
	loader := bytes.Repeat([]byte{0x5a, 0xa5}, 1024) // Exactly two 1024-byte blocks.
	script := []byte("#!ipxe\necho HCOS\n")
	address := startTFTPTestServer(t, loader, script)
	got := fetchTFTP(t, address, "bootx64.efi", 1024, true)
	if !bytes.Equal(got, loader) {
		t.Fatalf("loader bytes differ: got %d, want %d", len(got), len(loader))
	}
	got = fetchTFTP(t, address, "boot.ipxe", 512, false)
	if !bytes.Equal(got, script) {
		t.Fatalf("script bytes differ: got %q", got)
	}
}

func TestTFTPClampsLargeBlockRequest(t *testing.T) {
	address := startTFTPTestServer(t, []byte("loader"), nil)
	client := newTFTPClient(t)
	if _, err := client.WriteToUDP(tftpRequestPacket(1, "bootx64.efi", "octet", "blksize", "1468", "windowsize", "16"), address); err != nil {
		t.Fatal(err)
	}
	packet, peer := readTFTPPacket(t, client)
	if binary.BigEndian.Uint16(packet[:2]) != tftpOACK || !bytes.Contains(packet, []byte("blksize\x001024\x00")) || bytes.Contains(packet, []byte("windowsize")) {
		t.Fatalf("unexpected OACK for large blksize and unsupported window option: %v", packet)
	}
	if _, err := client.WriteToUDP(tftpACKPacket(0), peer); err != nil {
		t.Fatal(err)
	}
	packet, dataPeer := readTFTPPacket(t, client)
	if dataPeer.Port != peer.Port || binary.BigEndian.Uint16(packet[:2]) != tftpDATA || !bytes.Equal(packet[4:], []byte("loader")) {
		t.Fatalf("unexpected DATA after capped OACK: %v", packet)
	}
	if _, err := client.WriteToUDP(tftpACKPacket(1), peer); err != nil {
		t.Fatal(err)
	}
}

func TestTFTPRejectsOtherPathsWritesAndModes(t *testing.T) {
	address := startTFTPTestServer(t, []byte("loader"), nil)
	for _, test := range []struct {
		name   string
		packet []byte
		code   uint16
	}{
		{"traversal", tftpRequestPacket(1, "../bootx64.efi", "octet"), 1},
		{"unknown", tftpRequestPacket(1, "secret.txt", "octet"), 1},
		{"missing script", tftpRequestPacket(1, "boot.ipxe", "octet"), 2},
		{"write", tftpRequestPacket(2, "bootx64.efi", "octet"), 2},
		{"netascii", tftpRequestPacket(1, "bootx64.efi", "netascii"), 4},
		{"invalid blksize", tftpRequestPacket(1, "bootx64.efi", "octet", "blksize", "7"), 8},
		{"invalid tsize", tftpRequestPacket(1, "bootx64.efi", "octet", "tsize", "99"), 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newTFTPClient(t)
			if _, err := client.WriteToUDP(test.packet, address); err != nil {
				t.Fatal(err)
			}
			packet, _ := readTFTPPacket(t, client)
			if binary.BigEndian.Uint16(packet[:2]) != tftpERROR || binary.BigEndian.Uint16(packet[2:4]) != test.code {
				t.Fatalf("got %v, want ERROR code %d", packet, test.code)
			}
		})
	}
}

func TestTFTPRetriesMissingACKAndRejectsUnknownTransferID(t *testing.T) {
	address := startTFTPTestServer(t, []byte("loader"), nil)
	client := newTFTPClient(t)
	if _, err := client.WriteToUDP(tftpRequestPacket(1, "bootx64.efi", "octet"), address); err != nil {
		t.Fatal(err)
	}
	first, transfer := readTFTPPacket(t, client)
	if binary.BigEndian.Uint16(first[:2]) != tftpDATA || binary.BigEndian.Uint16(first[2:4]) != 1 {
		t.Fatalf("unexpected first DATA: %v", first)
	}
	if transfer.Port == address.Port {
		t.Fatal("transfer must use a separate server transfer ID")
	}
	attacker := newTFTPClient(t)
	if _, err := attacker.WriteToUDP(tftpACKPacket(1), transfer); err != nil {
		t.Fatal(err)
	}
	denied, _ := readTFTPPacket(t, attacker)
	if binary.BigEndian.Uint16(denied[:2]) != tftpERROR || binary.BigEndian.Uint16(denied[2:4]) != 5 {
		t.Fatalf("wrong transfer ID was not rejected: %v", denied)
	}
	retried, retryFrom := readTFTPPacket(t, client)
	if !bytes.Equal(retried, first) || retryFrom.Port != transfer.Port {
		t.Fatalf("missing ACK did not retransmit the same DATA packet: %v", retried)
	}
	if _, err := client.WriteToUDP(tftpACKPacket(1), transfer); err != nil {
		t.Fatal(err)
	}
}

func TestTFTPBlockNumberWrap(t *testing.T) {
	loader := bytes.Repeat([]byte("abcdefgh"), 1<<16)
	loader = append(loader, 'z') // Last DATA block after block number 0.
	address := startTFTPTestServer(t, loader, nil)
	got := fetchTFTP(t, address, "bootx64.efi", 8, false)
	if !bytes.Equal(got, loader) {
		t.Fatalf("block rollover corrupted %d-byte loader", len(loader))
	}
}

func startTFTPTestServer(t *testing.T, loader, script []byte) *net.UDPAddr {
	t.Helper()
	folder := t.TempDir()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().(*net.UDPAddr)
	config := TFTPConfig{ListenAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(address.Port))}
	if script != nil {
		config.ScriptPath = filepath.Join(folder, "boot.ipxe")
		if err := os.WriteFile(config.ScriptPath, script, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server, err := NewTFTPServer(config)
	if err != nil {
		t.Fatal(err)
	}
	if loader != nil {
		server.loader = loader
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("TFTP shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("TFTP server did not stop after cancellation")
		}
	})
	return address
}

func newTFTPClient(t *testing.T) *net.UDPConn {
	t.Helper()
	return newTFTPClientAt(t, "127.0.0.1")
}

func newTFTPClientAt(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func tftpRequestPacket(op uint16, name, mode string, options ...string) []byte {
	packet := make([]byte, 2)
	binary.BigEndian.PutUint16(packet, op)
	packet = append(packet, name...)
	packet = append(packet, 0)
	packet = append(packet, mode...)
	packet = append(packet, 0)
	for _, option := range options {
		packet = append(packet, option...)
		packet = append(packet, 0)
	}
	return packet
}

func tftpACKPacket(block uint16) []byte {
	return []byte{0, tftpACK, byte(block >> 8), byte(block)}
}

func readTFTPPacket(t *testing.T, client *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, peer, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Fatalf("TFTP packet too short: %v", buffer[:n])
	}
	return buffer[:n], peer
}

func fetchTFTP(t *testing.T, address *net.UDPAddr, name string, blockSize int, withTsize bool) []byte {
	t.Helper()
	return fetchTFTPFrom(t, address, name, blockSize, withTsize, "127.0.0.1")
}

func fetchTFTPFrom(t *testing.T, address *net.UDPAddr, name string, blockSize int, withTsize bool, sourceIP string) []byte {
	t.Helper()
	client := newTFTPClientAt(t, sourceIP)
	options := []string{"blksize", strconv.Itoa(blockSize)}
	if withTsize {
		options = append(options, "tsize", "0")
	}
	if _, err := client.WriteToUDP(tftpRequestPacket(1, name, "octet", options...), address); err != nil {
		t.Fatal(err)
	}
	packet, peer := readTFTPPacket(t, client)
	if binary.BigEndian.Uint16(packet[:2]) != tftpOACK {
		t.Fatalf("expected OACK, got %v", packet)
	}
	if !bytes.Contains(packet, []byte(fmt.Sprintf("blksize\x00%d\x00", blockSize))) {
		t.Fatalf("OACK did not accept requested blksize: %v", packet)
	}
	if withTsize && !bytes.Contains(packet, []byte("tsize\x002048\x00")) {
		t.Fatalf("OACK missing correct transfer size: %v", packet)
	}
	if _, err := client.WriteToUDP(tftpACKPacket(0), peer); err != nil {
		t.Fatal(err)
	}
	var result []byte
	for sequence := uint64(1); ; sequence++ {
		packet, sender := readTFTPPacket(t, client)
		if sender.Port != peer.Port || binary.BigEndian.Uint16(packet[:2]) != tftpDATA || binary.BigEndian.Uint16(packet[2:4]) != uint16(sequence) {
			t.Fatalf("unexpected DATA for sequence %d: %v from %v", sequence, packet[:4], sender)
		}
		result = append(result, packet[4:]...)
		if _, err := client.WriteToUDP(tftpACKPacket(uint16(sequence)), peer); err != nil {
			t.Fatal(err)
		}
		if len(packet)-4 < blockSize {
			return result
		}
	}
}

func TestTFTPServesOnlyRequestingNodesScript(t *testing.T) {
	config := testConfigWithPXE(t)
	config.Nodes[1].MAC, config.Nodes[1].IP = "52:54:00:12:34:57", "127.0.0.3"
	const special = "?+$;${variable}/=#%"
	config.Nodes[1].Token = strings.Repeat("&", 512-len(special)) + special
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "controller.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err = LoadConfig(path)
	if err != nil {
		t.Fatalf("consolidated node JSON rejected: %v", err)
	}
	runtime := config.RuntimePXE()
	dhcp, err := NewDHCPServer(runtime.DHCP)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTFTPServer(runtime.TFTP)
	if err != nil {
		t.Fatal(err)
	}
	address, done, cancel := runTFTPTestServer(t, server)
	t.Cleanup(func() {
		cancel()
		awaitTFTPShutdown(t, done)
	})
	api := testHandler(t, config)
	for index, node := range config.Nodes {
		mac, err := net.ParseMAC(node.MAC)
		if err != nil {
			t.Fatal(err)
		}
		discover := testDHCPRequest(1, 93, 2, 0, 9)
		copy(discover[28:34], mac)
		offer, ok := dhcp.HandlePacket(discover)
		if !ok || offer.NodeID != node.ID {
			t.Fatalf("DHCP did not identify node %s from its configured MAC", node.ID)
		}
		assignedIP := net.IP(offer.Packet[16:20]).String()
		if assignedIP != node.IP {
			t.Fatalf("node %s offered IP %s, want %s", node.ID, assignedIP, node.IP)
		}
		if got := string(testDHCPOptions(t, offer.Packet)[67]); got != "bootx64.efi" {
			t.Fatalf("DHCP firmware boot file = %q", got)
		}
		name := "boot.ipxe"
		if index == 1 {
			name = "boot/boot.ipxe"
		}
		script := string(fetchTFTPFrom(t, address, name, 512, false, assignedIP))
		if !strings.HasPrefix(script, "#!ipxe\nchain ") || strings.Count(script, "\n") != 2 {
			t.Fatalf("script contains unexpected commands: %q", script)
		}
		target, err := url.Parse(strings.TrimSuffix(strings.TrimPrefix(script, "#!ipxe\nchain "), "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if target.Scheme != "http" || target.Host != config.ServerIP || target.Path != "/boot/hcos.efi" || target.Fragment != "" || target.Query().Get("node") != node.ID || target.Query().Get("token") != node.Token || len(target.Query()) != 2 {
			t.Fatal("script did not preserve the requesting node's URL and credentials")
		}
		response := request(api, http.MethodGet, "/v1/nodes/"+node.ID+"/desired", target.Query().Get("token"), nil)
		if response.Code != http.StatusOK {
			t.Fatalf("TFTP script token could not authenticate node %s: HTTP %d", node.ID, response.Code)
		}
		if index == 1 && len(script) <= 1024 {
			t.Fatal("maximum encoded token did not exercise multiple transfer blocks")
		}
		if strings.Contains(script, "${") || strings.Contains(script, ";") {
			t.Fatal("unescaped iPXE syntax in generated script")
		}
	}
	unknownMAC := testDHCPRequest(1, 93, 2, 0, 9)
	unknownMAC[33] = 0xff
	if _, ok := dhcp.HandlePacket(unknownMAC); ok {
		t.Fatal("unknown MAC received a DHCP lease")
	}
	unknown := newTFTPClientAt(t, "127.0.0.4")
	if _, err := unknown.WriteToUDP(tftpRequestPacket(1, "boot.ipxe", "octet"), address); err != nil {
		t.Fatal(err)
	}
	packet, _ := readTFTPPacket(t, unknown)
	if binary.BigEndian.Uint16(packet[:2]) != tftpERROR || binary.BigEndian.Uint16(packet[2:4]) != 2 {
		t.Fatal("unknown source IP was not denied a node script")
	}
	// Firmware can fetch the public loader before receiving its DHCP lease.
	loader := fetchTFTPFrom(t, address, "bootx64.efi", 1024, false, "127.0.0.4")
	if !bytes.Equal(loader, embeddedIPXELoader) {
		t.Fatal("unknown source could not download the public loader")
	}
}

func TestTFTPCancelClosesPendingScriptTransfer(t *testing.T) {
	server, err := NewTFTPServer(TFTPConfig{
		ListenAddress: "127.0.0.1:1069",
		scripts:       map[string][]byte{"127.0.0.2": pxeBootScript("127.0.0.1", "compute-01", testPXENodeToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	address, done, cancel := runTFTPTestServer(t, server)
	t.Cleanup(cancel)
	client := newTFTPClientAt(t, "127.0.0.2")
	if _, err := client.WriteToUDP(tftpRequestPacket(1, "boot.ipxe", "octet"), address); err != nil {
		t.Fatal(err)
	}
	packet, _ := readTFTPPacket(t, client)
	if binary.BigEndian.Uint16(packet[:2]) != tftpDATA {
		t.Fatal("expected a pending script transfer")
	}
	// Do not acknowledge DATA: cancellation must stop the ACK wait.
	cancel()
	awaitTFTPShutdown(t, done)
	if len(server.sessions) != 0 {
		t.Fatal("script transfer survived server shutdown")
	}
}

func runTFTPTestServer(t *testing.T, server *TFTPServer) (*net.UDPAddr, <-chan error, context.CancelFunc) {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	return listener.LocalAddr().(*net.UDPAddr), done, cancel
}

func awaitTFTPShutdown(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("TFTP shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("TFTP server did not stop after cancellation")
	}
}
