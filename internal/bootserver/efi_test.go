package bootserver

import (
	"bytes"
	"testing"
)

func testBaseEFI() []byte {
	image := make([]byte, 0x600)
	copy(image, "MZ")
	put32(image, 0x3c, 0x80)
	copy(image[0x80:], []byte{'P', 'E', 0, 0})
	coff := 0x84
	image[coff] = 0x64
	image[coff+1] = 0x86
	image[coff+2] = 2
	image[coff+16] = 240
	optional := coff + 20
	image[optional] = 0x0b
	image[optional+1] = 0x02
	put32(image, optional+8, 0x400)
	put32(image, optional+32, 0x1000)
	put32(image, optional+36, 0x200)
	put32(image, optional+56, 0x3000)
	put32(image, optional+60, 0x200)
	image[optional+68] = 10
	put32(image, optional+108, 16)
	section := optional + 240
	copy(image[section:], ".text")
	put32(image, section+8, 3)
	put32(image, section+12, 0x1000)
	put32(image, section+16, 0x200)
	put32(image, section+20, 0x200)
	copy(image[0x200:], "EFI")
	section += sectionHeaderSize
	copy(image[section:], ".initrd")
	put32(image, section+8, 3)
	put32(image, section+12, 0x2000)
	put32(image, section+16, 0x200)
	put32(image, section+20, 0x400)
	put32(image, section+36, 0x40000040)
	copy(image[0x400:], []byte{0x1f, 0x8b, 0x08})
	return image
}

func TestAssembleEFI(t *testing.T) {
	base := testBaseEFI()
	supplement, err := buildCPIO([]byte(`{"node_id":"test"}`), []byte("cert"), bytes.Repeat([]byte("A"), 5000))
	if err != nil {
		t.Fatal(err)
	}
	final, err := AssembleEFI(base, supplement)
	if err != nil {
		t.Fatal(err)
	}
	initrd, err := InitrdSection(final)
	if err != nil {
		t.Fatal(err)
	}
	expected := append([]byte{0x1f, 0x8b, 0x08, 0}, supplement...)
	if !bytes.Equal(initrd, expected) {
		t.Fatal("the supplemental CPIO was not appended inside .initrd")
	}
	if !bytes.Equal(final[0x200:0x400], base[0x200:0x400]) {
		t.Fatal("EFI stub section changed")
	}
	if get32(final, 0x84+20+56) != 0x4000 {
		t.Fatal("SizeOfImage did not grow across page boundary")
	}
	if get32(final, 0x84+20+8) != 0x400+uint32(len(final)-len(base)) {
		t.Fatal("SizeOfInitializedData was not updated")
	}
	if len(final)%0x200 != 0 {
		t.Fatal("final file is not FileAlignment-aligned")
	}
}

func TestAssembleEFIRejectsUnsupportedImages(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"truncated", func([]byte) []byte { return []byte("MZ") }},
		{"signed base", func(image []byte) []byte {
			put32(image, 0x84+20+144, uint32(len(image)))
			put32(image, 0x84+20+148, 16)
			return append(image, make([]byte, 16)...)
		}},
		{"overlay", func(image []byte) []byte { return append(image, 0) }},
		{"initrd not last", func(image []byte) []byte {
			section := 0x84 + 20 + 240
			copy(image[section:section+8], ".initrd\x00")
			copy(image[section+sectionHeaderSize:section+sectionHeaderSize+8], ".text\x00\x00\x00")
			return image
		}},
	}
	supplement, err := buildCPIO([]byte("{}"), []byte("CA"), []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			image := tt.mutate(testBaseEFI())
			if _, err := AssembleEFI(image, supplement); err == nil {
				t.Fatal("expected unsupported image rejection")
			}
		})
	}
}

func TestVerifySignedEFI(t *testing.T) {
	base := testBaseEFI()
	signed := append(append([]byte(nil), base...), make([]byte, 16)...)
	put32(signed, 0x84+20+144, uint32(len(base)))
	put32(signed, 0x84+20+148, 16)
	initrd, err := InitrdSection(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignedEFI(signed, initrd); err != nil {
		t.Fatal(err)
	}
	signed[0x400] ^= 1
	if err := verifySignedEFI(signed, initrd); err == nil {
		t.Fatal("modified initramfs accepted")
	}
}
