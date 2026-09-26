package bootserver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	pe32PlusMagic     = 0x20b
	peAMD64           = 0x8664
	efiApplication    = 10
	sectionHeaderSize = 40
)

type initrdLocation struct {
	optionalHeader   int
	sectionHeader    int
	rawOffset        int
	virtualAddress   uint32
	virtualSize      uint32
	rawSize          uint32
	fileAlignment    uint32
	sectionAlignment uint32
}

// AssembleEFI appends a raw newc archive to the existing gzip initramfs inside
// an unsigned x86-64 UKI. The input UKI must have .initrd as its final section.
func AssembleEFI(base, supplemental []byte) ([]byte, error) {
	if len(supplemental) < 110 || !bytes.HasPrefix(supplemental, []byte("070701")) {
		return nil, errors.New("supplement is not a newc CPIO archive")
	}
	location, err := locateInitrd(base, false)
	if err != nil {
		return nil, err
	}
	start := uint64(location.rawOffset)
	baseEnd := start + uint64(location.virtualSize)
	padded := alignUp(baseEnd, 4)
	newVirtualSize := padded - start + uint64(len(supplemental))
	newRawSize := alignUp(newVirtualSize, uint64(location.fileAlignment))
	newFileSize := start + newRawSize
	newImageSize := alignUp(uint64(location.virtualAddress)+newVirtualSize, uint64(location.sectionAlignment))
	if newVirtualSize > math.MaxUint32 || newRawSize > math.MaxUint32 ||
		newImageSize > math.MaxUint32 || newFileSize > math.MaxInt {
		return nil, errors.New("injected EFI exceeds PE size limit")
	}
	result := make([]byte, int(newFileSize))
	copy(result, base[:int(baseEnd)])
	copy(result[int(padded):], supplemental)
	put32(result, location.sectionHeader+8, uint32(newVirtualSize))
	put32(result, location.sectionHeader+16, uint32(newRawSize))
	put32(result, location.optionalHeader+56, uint32(newImageSize))
	initialized := uint64(get32(base, location.optionalHeader+8)) + newRawSize - uint64(location.rawSize)
	if initialized > math.MaxUint32 {
		return nil, errors.New("initialized data size exceeds PE limit")
	}
	put32(result, location.optionalHeader+8, uint32(initialized))
	// The base UKI has no PE checksum. Zeroing it also avoids retaining a stale one.
	put32(result, location.optionalHeader+64, 0)
	return result, nil
}

// InitrdSection returns the meaningful bytes of the .initrd PE section.
func InitrdSection(image []byte) ([]byte, error) {
	location, err := locateInitrd(image, false)
	if err != nil {
		return nil, err
	}
	return image[location.rawOffset : location.rawOffset+int(location.virtualSize)], nil
}

func locateInitrd(image []byte, signed bool) (initrdLocation, error) {
	var location initrdLocation
	if len(image) < 64 || !bytes.Equal(image[:2], []byte("MZ")) {
		return location, errors.New("image lacks a DOS header")
	}
	peOffset := uint64(get32(image, 0x3c))
	if peOffset+24 > uint64(len(image)) || !bytes.Equal(image[peOffset:peOffset+4], []byte{'P', 'E', 0, 0}) {
		return location, errors.New("image lacks a PE signature")
	}
	coff := int(peOffset) + 4
	if get16(image, coff) != peAMD64 {
		return location, errors.New("EFI image is not x86-64")
	}
	sectionCount := int(get16(image, coff+2))
	if sectionCount == 0 || sectionCount > 96 {
		return location, errors.New("invalid PE section count")
	}
	if get32(image, coff+8) != 0 || get32(image, coff+12) != 0 {
		return location, errors.New("PE image contains a COFF symbol table")
	}
	optionalSize := int(get16(image, coff+16))
	optional := coff + 20
	sectionTable := optional + optionalSize
	if optionalSize < 152 || uint64(sectionTable)+uint64(sectionCount)*sectionHeaderSize > uint64(len(image)) {
		return location, errors.New("truncated PE optional header or section table")
	}
	if get16(image, optional) != pe32PlusMagic || get16(image, optional+68) != efiApplication {
		return location, errors.New("image is not a PE32+ EFI application")
	}
	sizeHeaders := get32(image, optional+60)
	if uint64(sectionTable)+uint64(sectionCount)*sectionHeaderSize > uint64(sizeHeaders) ||
		uint64(sizeHeaders) > uint64(len(image)) {
		return location, errors.New("invalid PE header size")
	}
	if get32(image, optional+108) < 5 {
		return location, errors.New("PE security directory is unavailable")
	}
	certificateOffset := uint64(get32(image, optional+144))
	certificateSize := uint64(get32(image, optional+148))
	if !signed && (certificateOffset != 0 || certificateSize != 0) {
		return location, errors.New("signed base EFI is unsupported")
	}
	if signed && (certificateOffset == 0 || certificateSize == 0) {
		return location, errors.New("signer returned an unsigned EFI")
	}
	fileAlignment := get32(image, optional+36)
	sectionAlignment := get32(image, optional+32)
	if fileAlignment == 0 || sectionAlignment == 0 || sectionAlignment < fileAlignment ||
		fileAlignment&(fileAlignment-1) != 0 || sectionAlignment&(sectionAlignment-1) != 0 {
		return location, errors.New("invalid PE alignments")
	}
	var maxRawEnd uint64
	var maxVirtualEnd uint64
	var initrdCount int
	for index := 0; index < sectionCount; index++ {
		section := sectionTable + index*sectionHeaderSize
		rawSize := get32(image, section+16)
		rawOffset := get32(image, section+20)
		virtualSize := get32(image, section+8)
		virtualAddress := get32(image, section+12)
		if rawSize == 0 || rawOffset == 0 || virtualSize == 0 || virtualSize > rawSize ||
			rawOffset%fileAlignment != 0 || rawSize%fileAlignment != 0 || virtualAddress%sectionAlignment != 0 {
			return location, fmt.Errorf("invalid PE section %d", index)
		}
		rawEnd := uint64(rawOffset) + uint64(rawSize)
		virtualEnd := uint64(virtualAddress) + alignUp(uint64(virtualSize), uint64(sectionAlignment))
		if rawEnd > uint64(len(image)) || uint64(rawOffset) < uint64(sizeHeaders) {
			return location, fmt.Errorf("PE section %d is outside the image", index)
		}
		if uint64(rawOffset) < maxRawEnd || uint64(virtualAddress) < maxVirtualEnd {
			return location, errors.New("PE sections overlap or are out of order")
		}
		maxRawEnd, maxVirtualEnd = rawEnd, virtualEnd
		if bytes.Equal(bytes.TrimRight(image[section:section+8], "\x00"), []byte(".initrd")) {
			initrdCount++
			if index != sectionCount-1 {
				return location, errors.New(".initrd must be the final PE section")
			}
			if get32(image, section+36)&0x40 == 0 {
				return location, errors.New(".initrd must be initialized data")
			}
			location = initrdLocation{
				optionalHeader:   optional,
				sectionHeader:    section,
				rawOffset:        int(rawOffset),
				virtualAddress:   virtualAddress,
				virtualSize:      virtualSize,
				rawSize:          rawSize,
				fileAlignment:    fileAlignment,
				sectionAlignment: sectionAlignment,
			}
		}
	}
	if initrdCount != 1 {
		return location, errors.New("EFI must have one terminal .initrd section")
	}
	if signed {
		if certificateOffset < maxRawEnd || certificateOffset%8 != 0 ||
			certificateOffset+certificateSize != uint64(len(image)) {
			return location, errors.New("signed EFI has an invalid certificate overlay")
		}
	} else if maxRawEnd != uint64(len(image)) {
		return location, errors.New("unsigned EFI has an unsupported overlay")
	}
	if maxVirtualEnd > math.MaxUint32 || uint64(get32(image, optional+56)) != maxVirtualEnd {
		return location, errors.New("PE SizeOfImage does not match its sections")
	}
	initrd := image[location.rawOffset : location.rawOffset+int(location.virtualSize)]
	if !bytes.HasPrefix(initrd, []byte{0x1f, 0x8b}) {
		return location, errors.New("base .initrd must be gzip-compressed")
	}
	return location, nil
}

func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}

func get16(data []byte, offset int) uint16 { return binary.LittleEndian.Uint16(data[offset:]) }
func get32(data []byte, offset int) uint32 { return binary.LittleEndian.Uint32(data[offset:]) }
func put32(data []byte, offset int, value uint32) {
	binary.LittleEndian.PutUint32(data[offset:], value)
}

// verifySignedEFI checks that the signer produced a PE certificate and preserved
// the exact initramfs that was assembled before signing.
func verifySignedEFI(image, unsignedInitrd []byte) error {
	location, err := locateInitrd(image, true)
	if err != nil {
		return err
	}
	finalInitrd := image[location.rawOffset : location.rawOffset+int(location.virtualSize)]
	if !bytes.Equal(finalInitrd, unsignedInitrd) {
		return errors.New("signer changed the initramfs payload")
	}
	return nil
}
