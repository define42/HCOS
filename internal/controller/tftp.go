package controller

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tftpMaxRequestBytes = 1024
	tftpMaxLoaderBytes  = 16 << 20
	tftpMaxScriptBytes  = 64 << 10
	tftpDefaultBlock    = 512
	tftpMaxBlock        = 1024
	tftpMaxSessions     = 32
	tftpRetryInterval   = 2 * time.Second
	tftpRetryCount      = 5
	tftpSessionLimit    = 10 * time.Minute
)

const (
	tftpRRQ   = 1
	tftpWRQ   = 2
	tftpDATA  = 3
	tftpACK   = 4
	tftpERROR = 5
	tftpOACK  = 6
)

// TFTPConfig identifies the two public boot assets. TFTP never serves a path
// supplied by a client and never carries node credentials or personalized EFI.
type TFTPConfig struct {
	ListenAddress string `json:"listen_address"`
	LoaderPath    string `json:"loader_path"`
	ScriptPath    string `json:"script_path,omitempty"`
}

// Validate rejects invalid listener and asset paths before the UDP port opens.
func (c TFTPConfig) Validate() error {
	_, port, err := net.SplitHostPort(c.ListenAddress)
	if err != nil {
		return fmt.Errorf("TFTP listen_address: %w", err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("TFTP listen_address must use a UDP port from 1 to 65535")
	}
	if !cleanAbsolutePath(c.LoaderPath) {
		return errors.New("TFTP loader_path must be a clean absolute file path")
	}
	if c.ScriptPath != "" && !cleanAbsolutePath(c.ScriptPath) {
		return errors.New("TFTP script_path must be a clean absolute file path")
	}
	if c.ScriptPath != "" && c.ScriptPath == c.LoaderPath {
		return errors.New("TFTP loader_path and script_path must differ")
	}
	return nil
}

func cleanAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

// TFTPServer serves a small, fixed set of public boot assets over UDP.
// Serve owns each transfer socket; the caller owns the initial UDP listener.
type TFTPServer struct {
	config   TFTPConfig
	sessions chan struct{}
}

// NewTFTPServer verifies the configured assets and constructs a bounded server.
func NewTFTPServer(config TFTPConfig) (*TFTPServer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := checkTFTPAsset(config.LoaderPath, tftpMaxLoaderBytes); err != nil {
		return nil, fmt.Errorf("TFTP loader: %w", err)
	}
	if config.ScriptPath != "" {
		if err := checkTFTPAsset(config.ScriptPath, tftpMaxScriptBytes); err != nil {
			return nil, fmt.Errorf("TFTP script: %w", err)
		}
	}
	return &TFTPServer{config: config, sessions: make(chan struct{}, tftpMaxSessions)}, nil
}

// Serve accepts only read requests for bootx64.efi and, when configured,
// boot.ipxe. Cancelling ctx closes active transfer sockets and waits for them.
func (s *TFTPServer) Serve(ctx context.Context, conn *net.UDPConn) error {
	if s == nil || conn == nil {
		return errors.New("TFTP server and listener are required")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	var transfers sync.WaitGroup
	defer func() {
		cancel()
		stop()
		transfers.Wait()
	}()

	packet := make([]byte, tftpMaxRequestBytes+1)
	for {
		n, peer, err := conn.ReadFromUDP(packet)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("TFTP receive request: %w", err)
		}
		if n > tftpMaxRequestBytes {
			writeTFTPError(conn, peer, 4, "request too large")
			continue
		}
		request, code, message := parseTFTPRRQ(packet[:n])
		if code != 0 {
			writeTFTPError(conn, peer, code, message)
			continue
		}
		path, limit := s.assetForName(request.filename)
		if path == "" {
			writeTFTPError(conn, peer, 1, "file not found")
			continue
		}
		select {
		case s.sessions <- struct{}{}:
		default:
			writeTFTPError(conn, peer, 0, "server busy")
			continue
		}
		file, size, err := openTFTPAsset(path, limit)
		if err != nil {
			<-s.sessions
			writeTFTPError(conn, peer, 1, "file unavailable")
			continue
		}
		transferConn, err := newTFTPTransferSocket(conn, peer)
		if err != nil {
			_ = file.Close()
			<-s.sessions
			writeTFTPError(conn, peer, 0, "server busy")
			continue
		}
		transfers.Add(1)
		go func() {
			defer transfers.Done()
			defer func() { <-s.sessions }()
			defer file.Close()
			defer transferConn.Close()
			s.transfer(ctx, transferConn, peer, file, size, request.options)
		}()
	}
}

func (s *TFTPServer) assetForName(name string) (string, int64) {
	switch name {
	case "bootx64.efi":
		return s.config.LoaderPath, tftpMaxLoaderBytes
	case "boot.ipxe":
		if s.config.ScriptPath != "" {
			return s.config.ScriptPath, tftpMaxScriptBytes
		}
	}
	return "", 0
}

func checkTFTPAsset(path string, maximum int64) error {
	file, _, err := openTFTPAsset(path, maximum)
	if err != nil {
		return err
	}
	return file.Close()
}

func openTFTPAsset(path string, maximum int64) (*os.File, int64, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !before.Mode().IsRegular() {
		return nil, 0, errors.New("asset must be a regular file, not a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() <= 0 || after.Size() > maximum {
		_ = file.Close()
		return nil, 0, fmt.Errorf("asset changed or must be 1 to %d bytes", maximum)
	}
	return file, after.Size(), nil
}

type tftpRequest struct {
	filename string
	options  map[string]string
}

func parseTFTPRRQ(packet []byte) (tftpRequest, uint16, string) {
	if len(packet) < 4 || packet[0] != 0 {
		return tftpRequest{}, 4, "malformed request"
	}
	switch binary.BigEndian.Uint16(packet[:2]) {
	case tftpWRQ:
		return tftpRequest{}, 2, "write access denied"
	case tftpRRQ:
	default:
		return tftpRequest{}, 4, "illegal operation"
	}
	if packet[len(packet)-1] != 0 {
		return tftpRequest{}, 4, "malformed request"
	}
	fields := bytes.Split(packet[2:], []byte{0})
	if len(fields) < 3 || len(fields)%2 == 0 || len(fields[0]) == 0 || len(fields[1]) == 0 {
		return tftpRequest{}, 4, "malformed request"
	}
	if !strings.EqualFold(string(fields[1]), "octet") {
		return tftpRequest{}, 4, "only octet mode is supported"
	}
	request := tftpRequest{filename: string(fields[0]), options: make(map[string]string)}
	for i := 2; i < len(fields)-1; i += 2 {
		key := strings.ToLower(string(fields[i]))
		if key == "" || len(fields[i+1]) == 0 {
			return tftpRequest{}, 8, "invalid option"
		}
		if _, exists := request.options[key]; exists {
			return tftpRequest{}, 8, "duplicate option"
		}
		request.options[key] = string(fields[i+1])
	}
	return request, 0, ""
}

func newTFTPTransferSocket(listener *net.UDPConn, peer *net.UDPAddr) (*net.UDPConn, error) {
	local := listener.LocalAddr().(*net.UDPAddr)
	ip := local.IP
	network := "udp6"
	if peer.IP.To4() != nil {
		network = "udp4"
		if ip == nil || ip.To4() == nil {
			ip = net.IPv4zero
		}
	} else if ip == nil || ip.To4() != nil {
		ip = net.IPv6unspecified
	}
	return net.ListenUDP(network, &net.UDPAddr{IP: ip, Zone: local.Zone})
}

func (s *TFTPServer) transfer(ctx context.Context, conn *net.UDPConn, peer *net.UDPAddr, file *os.File, size int64, options map[string]string) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(tftpSessionLimit)
	blockSize := tftpDefaultBlock
	oack := []byte{0, tftpOACK}
	if requested, exists := options["blksize"]; exists {
		value, ok := decimalTFTPOption(requested)
		if !ok || value < 8 || value > 65464 {
			writeTFTPError(conn, peer, 8, "invalid blksize")
			return
		}
		blockSize = min(value, tftpMaxBlock)
		oack = appendTFTPOption(oack, "blksize", strconv.Itoa(blockSize))
	}
	if requested, exists := options["tsize"]; exists {
		value, ok := decimalTFTPOption(requested)
		if !ok || value != 0 {
			writeTFTPError(conn, peer, 8, "invalid tsize")
			return
		}
		oack = appendTFTPOption(oack, "tsize", strconv.FormatInt(size, 10))
	}
	if len(oack) > 2 {
		if !sendTFTPAndAwaitACK(ctx, conn, peer, oack, 0, deadline) {
			return
		}
	}

	for sequence := uint64(1); ; sequence++ {
		offset := int64(sequence-1) * int64(blockSize)
		count := 0
		if offset < size {
			count = int(min(size-offset, int64(blockSize)))
		}
		data := make([]byte, 4+count)
		binary.BigEndian.PutUint16(data[:2], tftpDATA)
		binary.BigEndian.PutUint16(data[2:4], uint16(sequence)) // RFC 1350's 16-bit block number wraps.
		if count > 0 {
			n, err := file.ReadAt(data[4:], offset)
			if n != count || (err != nil && err != io.EOF) {
				writeTFTPError(conn, peer, 0, "asset read failed")
				return
			}
		}
		if !sendTFTPAndAwaitACK(ctx, conn, peer, data, uint16(sequence), deadline) {
			return
		}
		if count < blockSize {
			return
		}
	}
}

func decimalTFTPOption(value string) (int, bool) {
	if value == "" || len(value) > 8 {
		return 0, false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	number, err := strconv.Atoi(value)
	return number, err == nil
}

func appendTFTPOption(packet []byte, key, value string) []byte {
	packet = append(packet, key...)
	packet = append(packet, 0)
	packet = append(packet, value...)
	return append(packet, 0)
}

func sendTFTPAndAwaitACK(ctx context.Context, conn *net.UDPConn, peer *net.UDPAddr, packet []byte, block uint16, sessionDeadline time.Time) bool {
	response := make([]byte, 2048)
	for attempt := 0; attempt < tftpRetryCount && ctx.Err() == nil && time.Now().Before(sessionDeadline); attempt++ {
		if _, err := conn.WriteToUDP(packet, peer); err != nil {
			return false
		}
		readDeadline := minTime(time.Now().Add(tftpRetryInterval), sessionDeadline)
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			return false
		}
		for {
			n, sender, err := conn.ReadFromUDP(response)
			if err != nil {
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					break
				}
				return false
			}
			if !sameTFTPPeer(sender, peer) {
				writeTFTPError(conn, sender, 5, "unknown transfer ID")
				continue
			}
			if n == 4 && binary.BigEndian.Uint16(response[:2]) == tftpACK && binary.BigEndian.Uint16(response[2:4]) == block {
				return true
			}
			if n >= 2 && binary.BigEndian.Uint16(response[:2]) == tftpERROR {
				return false
			}
			// Old, malformed, and unsolicited acknowledgments cannot advance a transfer.
		}
	}
	return false
}

func sameTFTPPeer(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func writeTFTPError(conn *net.UDPConn, peer *net.UDPAddr, code uint16, message string) {
	packet := make([]byte, 4, 5+len(message))
	binary.BigEndian.PutUint16(packet[:2], tftpERROR)
	binary.BigEndian.PutUint16(packet[2:4], code)
	packet = append(packet, message...)
	packet = append(packet, 0)
	_, _ = conn.WriteToUDP(packet, peer)
}
