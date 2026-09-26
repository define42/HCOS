package bootserver

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type assets struct {
	base      []byte
	agent     []byte
	ca        []byte
	baseHash  [32]byte
	agentHash [32]byte
	caHash    [32]byte
}

func (c Config) paths(node Node) (base, agent, ca string) {
	return filepath.Join(c.ImagesDir, "hcos-"+node.HCOSVersion+".efi"),
		filepath.Join(c.AgentsDir, node.AgentVersion, "hcos-agent"),
		filepath.Join(c.TrustDir, node.CAVersion, "root-ca.crt")
}

func loadAssets(c Config, node Node) (assets, error) {
	var a assets
	basePath, agentPath, caPath := c.paths(node)
	var err error
	if a.base, err = readRegular(basePath, 2<<30, false); err != nil {
		return a, fmt.Errorf("load base EFI: %w", err)
	}
	if a.agent, err = readRegular(agentPath, 128<<20, true); err != nil {
		return a, fmt.Errorf("load agent: %w", err)
	}
	if a.ca, err = readRegular(caPath, 4<<20, false); err != nil {
		return a, fmt.Errorf("load CA: %w", err)
	}
	if err := validateCertificate(a.ca); err != nil {
		return a, fmt.Errorf("invalid CA: %w", err)
	}
	a.baseHash = sha256.Sum256(a.base)
	a.agentHash = sha256.Sum256(a.agent)
	a.caHash = sha256.Sum256(a.ca)
	if err := verifyExpectedHash("base EFI", node.HCOSSHA256, a.baseHash); err != nil {
		return a, err
	}
	if err := verifyExpectedHash("agent", node.AgentSHA256, a.agentHash); err != nil {
		return a, err
	}
	if err := verifyExpectedHash("CA", node.CASHA256, a.caHash); err != nil {
		return a, err
	}
	return a, nil
}

func readRegular(path string, limit int64, executable bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("asset must be a nonempty regular file within its size limit")
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("agent file is not executable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("asset changed while being read")
	}
	return data, nil
}

func verifyExpectedHash(name, expected string, actual [32]byte) error {
	if expected == "" {
		return nil
	}
	digest, err := hex.DecodeString(expected)
	if err != nil || len(digest) != sha256.Size || !bytes.Equal(digest, actual[:]) {
		return fmt.Errorf("%s SHA-256 does not match its configured digest", name)
	}
	return nil
}

func validateCertificate(data []byte) error {
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("CA file contains non-certificate data")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("CA file must contain only PEM certificates")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return errors.New("CA file contains an invalid or non-CA certificate")
		}
		count++
		data = rest
	}
	if count == 0 {
		return errors.New("CA file contains no certificates")
	}
	return nil
}
