package bootserver

import (
	"bytes"
	"errors"
	"fmt"
	"math"
)

type cpioEntry struct {
	name string
	mode uint32
	data []byte
}

// buildCPIO creates a deterministic root-owned newc archive.
func buildCPIO(configJSON, certificate, agent []byte) ([]byte, error) {
	entries := []cpioEntry{
		{"etc", 0o040755, nil},
		{"etc/hcos", 0o040755, nil},
		{"etc/hcos/root-ca.crt", 0o100644, certificate},
		{"etc/hcos/config.json", 0o100600, configJSON},
		{"usr", 0o040755, nil},
		{"usr/local", 0o040755, nil},
		{"usr/local/bin", 0o040755, nil},
		{"usr/local/bin/hcos-agent", 0o100755, agent},
		{"TRAILER!!!", 0, nil},
	}
	var result bytes.Buffer
	for index, entry := range entries {
		if err := writeCPIOEntry(&result, uint32(index+1), entry); err != nil {
			return nil, err
		}
	}
	return result.Bytes(), nil
}

func writeCPIOEntry(dst *bytes.Buffer, inode uint32, entry cpioEntry) error {
	if len(entry.name)+1 > math.MaxUint32 || len(entry.data) > math.MaxUint32 {
		return errors.New("CPIO entry exceeds newc field size")
	}
	if bytes.IndexByte([]byte(entry.name), 0) >= 0 || entry.name == "" {
		return errors.New("invalid CPIO entry name")
	}
	nlink := uint32(1)
	if entry.mode&0o170000 == 0o040000 {
		nlink = 2
	}
	fields := [...]uint32{
		inode, entry.mode, 0, 0, nlink, 0,
		uint32(len(entry.data)), 0, 0, 0, 0,
		uint32(len(entry.name) + 1), 0,
	}
	dst.WriteString("070701")
	for _, value := range fields {
		_, _ = fmt.Fprintf(dst, "%08x", value)
	}
	dst.WriteString(entry.name)
	dst.WriteByte(0)
	for dst.Len()%4 != 0 {
		dst.WriteByte(0)
	}
	dst.Write(entry.data)
	for dst.Len()%4 != 0 {
		dst.WriteByte(0)
	}
	return nil
}
