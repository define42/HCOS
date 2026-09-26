package controller

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestTFTPConfigAndAssetValidation(t *testing.T) {
	folder := t.TempDir()
	loader := filepath.Join(folder, "loader.efi")
	if err := os.WriteFile(loader, []byte("PE-loader"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := TFTPConfig{ListenAddress: "127.0.0.1:1069", LoaderPath: loader}
	if _, err := NewTFTPServer(config); err != nil {
		t.Fatalf("valid loader: %v", err)
	}
	bad := config
	bad.LoaderPath = "relative.efi"
	if _, err := NewTFTPServer(bad); err == nil {
		t.Fatal("relative loader path accepted")
	}
	bad = config
	bad.ListenAddress = "127.0.0.1:0"
	if _, err := NewTFTPServer(bad); err == nil {
		t.Fatal("zero listen port accepted")
	}
	symlink := filepath.Join(folder, "linked.efi")
	if err := os.Symlink(loader, symlink); err != nil {
		t.Fatal(err)
	}
	bad = config
	bad.LoaderPath = symlink
	if _, err := NewTFTPServer(bad); err == nil {
		t.Fatal("symlinked loader accepted")
	}
	bad = config
	bad.ScriptPath = loader
	if _, err := NewTFTPServer(bad); err == nil {
		t.Fatal("loader reused as script accepted")
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
		{"missing script", tftpRequestPacket(1, "boot.ipxe", "octet"), 1},
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
	loaderPath := filepath.Join(folder, "loader.efi")
	if err := os.WriteFile(loaderPath, loader, 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().(*net.UDPAddr)
	config := TFTPConfig{ListenAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(address.Port)), LoaderPath: loaderPath}
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
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
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
	client := newTFTPClient(t)
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
