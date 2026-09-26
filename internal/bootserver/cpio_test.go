package bootserver

import (
	"bytes"
	"strconv"
	"testing"
)

func TestBuildCPIO(t *testing.T) {
	config := []byte(`{"api_version":"hcos/v1"}`)
	ca := []byte("CA certificate")
	agent := []byte("#!/bin/sh\n")
	archive, err := buildCPIO(config, ca, agent)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]struct {
		mode uint64
		data []byte
	}{
		"etc":                      {0o040755, nil},
		"etc/hcos":                 {0o040755, nil},
		"etc/hcos/root-ca.crt":     {0o100644, ca},
		"etc/hcos/config.json":     {0o100600, config},
		"usr":                      {0o040755, nil},
		"usr/local":                {0o040755, nil},
		"usr/local/bin":            {0o040755, nil},
		"usr/local/bin/hcos-agent": {0o100755, agent},
		"TRAILER!!!":               {0, nil},
	}
	offset := 0
	for len(expected) > 0 {
		if offset+110 > len(archive) || string(archive[offset:offset+6]) != "070701" {
			t.Fatal("missing newc header")
		}
		fields := make([]uint64, 13)
		for i := range fields {
			value, err := strconv.ParseUint(string(archive[offset+6+i*8:offset+14+i*8]), 16, 32)
			if err != nil {
				t.Fatal(err)
			}
			fields[i] = value
		}
		offset += 110
		nameLen := int(fields[11])
		if nameLen < 1 || offset+nameLen > len(archive) || archive[offset+nameLen-1] != 0 {
			t.Fatal("invalid name field")
		}
		name := string(archive[offset : offset+nameLen-1])
		offset += nameLen
		offset = int(alignUp(uint64(offset), 4))
		size := int(fields[6])
		if offset+size > len(archive) {
			t.Fatal("truncated data")
		}
		item, found := expected[name]
		if !found {
			t.Fatalf("unexpected or duplicate entry %q", name)
		}
		if fields[1] != item.mode || fields[2] != 0 || fields[3] != 0 ||
			!bytes.Equal(archive[offset:offset+size], item.data) {
			t.Fatalf("wrong mode, owner, or data for %q", name)
		}
		delete(expected, name)
		offset += size
		offset = int(alignUp(uint64(offset), 4))
	}
	if offset != len(archive) {
		t.Fatal("bytes found after trailer")
	}
}
