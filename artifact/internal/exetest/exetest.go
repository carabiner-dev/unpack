// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package exetest synthesizes minimal executables for tests: just enough
// ELF, PE or Mach-O structure for the standard library's debug packages to
// parse them and find a named section with the given contents. None of
// them can run; they are fixtures for readers of embedded data.
package exetest

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
)

// ELF returns a 64-bit little-endian ELF executable holding one section
// with the given name and contents.
func ELF(section string, data []byte) []byte {
	const hdrSize = 64
	shstrtab := []byte("\x00" + section + "\x00.shstrtab\x00")
	dataOff := uint64(hdrSize)
	strOff := dataOff + uint64(len(data))
	shOff := strOff + uint64(len(shstrtab))

	var buf bytes.Buffer
	must(binary.Write(&buf, binary.LittleEndian, elf.Header64{
		Ident: [16]byte{
			0x7f, 'E', 'L', 'F',
			byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT),
		},
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Shoff:     shOff,
		Ehsize:    hdrSize,
		Shentsize: 64,
		Shnum:     3,
		Shstrndx:  2,
	}))
	buf.Write(data)
	buf.Write(shstrtab)
	must(binary.Write(&buf, binary.LittleEndian, elf.Section64{}))
	must(binary.Write(&buf, binary.LittleEndian, elf.Section64{
		Name: 1, Type: uint32(elf.SHT_PROGBITS), Off: dataOff, Size: uint64(len(data)), Addralign: 1,
	}))
	must(binary.Write(&buf, binary.LittleEndian, elf.Section64{
		Name: uint32(1 + len(section) + 1), Type: uint32(elf.SHT_STRTAB), Off: strOff, Size: uint64(len(shstrtab)), Addralign: 1, //nolint:gosec // tiny fixtures
	}))
	return buf.Bytes()
}

// PE returns an x86-64 PE executable holding one section with the given
// name (at most 8 bytes) and contents.
func PE(section string, data []byte) []byte {
	const (
		peOff    = 0x40
		fhSize   = 20
		shSize   = 40
		optSize  = 0 // no optional header, as in an object file
		dataOff  = peOff + 4 + fhSize + optSize + shSize
		dataAddr = 0x1000
	)
	var buf bytes.Buffer
	dos := make([]byte, peOff)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], peOff)
	buf.Write(dos)
	buf.WriteString("PE\x00\x00")
	must(binary.Write(&buf, binary.LittleEndian, pe.FileHeader{
		Machine:              pe.IMAGE_FILE_MACHINE_AMD64,
		NumberOfSections:     1,
		SizeOfOptionalHeader: optSize,
		Characteristics:      pe.IMAGE_FILE_EXECUTABLE_IMAGE,
	}))
	var name [8]uint8
	copy(name[:], section)
	must(binary.Write(&buf, binary.LittleEndian, pe.SectionHeader32{
		Name:             name,
		VirtualSize:      uint32(len(data)), //nolint:gosec // tiny fixtures
		VirtualAddress:   dataAddr,
		SizeOfRawData:    uint32(len(data)), //nolint:gosec // tiny fixtures
		PointerToRawData: dataOff,
		Characteristics:  pe.IMAGE_SCN_CNT_INITIALIZED_DATA,
	}))
	buf.Write(data)
	return buf.Bytes()
}

// MachO returns a 64-bit little-endian Mach-O executable holding one
// section with the given name (at most 16 bytes) in the __DATA segment.
func MachO(section string, data []byte) []byte {
	const (
		hdrSize  = 32
		segSize  = 72
		sectSize = 80
		dataOff  = hdrSize + segSize + sectSize
		vmaddr   = 0x100000000
	)
	var buf bytes.Buffer
	must(binary.Write(&buf, binary.LittleEndian, macho.FileHeader{
		Magic:  macho.Magic64,
		Cpu:    macho.CpuAmd64,
		SubCpu: 3,
		Type:   macho.TypeExec,
		Ncmd:   1,
		Cmdsz:  segSize + sectSize,
	}))
	// The 64-bit header has a reserved word after the fields FileHeader
	// models, which the parser skips.
	must(binary.Write(&buf, binary.LittleEndian, uint32(0)))
	var segname, sectname [16]byte
	copy(segname[:], "__DATA")
	copy(sectname[:], section)
	must(binary.Write(&buf, binary.LittleEndian, macho.Segment64{
		Cmd:     macho.LoadCmdSegment64,
		Len:     segSize + sectSize,
		Name:    segname,
		Addr:    vmaddr,
		Memsz:   uint64(len(data)),
		Offset:  dataOff,
		Filesz:  uint64(len(data)),
		Maxprot: 3,
		Prot:    3,
		Nsect:   1,
	}))
	must(binary.Write(&buf, binary.LittleEndian, macho.Section64{
		Name:   sectname,
		Seg:    segname,
		Addr:   vmaddr,
		Size:   uint64(len(data)),
		Offset: dataOff,
	}))
	// Pad the header to the section offset in case the structs are shorter
	// than the constants assume.
	for buf.Len() < dataOff {
		buf.WriteByte(0)
	}
	buf.Write(data)
	return buf.Bytes()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
