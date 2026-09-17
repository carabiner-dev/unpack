// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package executable holds what the artifact decomposers for compiled
// programs share: recognizing an executable by its magic number and
// reading a named section out of it, whatever its object format.
package executable

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"io"
)

// Magic reports whether header, the first bytes of a file, opens an
// executable in one of the formats the decomposers read: ELF, PE or
// Mach-O (thin, either endianness, 32 or 64 bit).
func Magic(header []byte) bool {
	if len(header) < 4 {
		return false
	}
	switch string(header[:4]) {
	case "\x7fELF",
		"\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", // Mach-O 32/64, big endian
		"\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe": // Mach-O 32/64, little endian
		return true
	}
	return header[0] == 'M' && header[1] == 'Z'
}

// Section returns the contents of the named section of the executable, or
// nil when the file has no such section, is not an executable in a format
// Section reads, or is a malformed one. Only a failure reading the section
// data of a well-formed file is an error: a decomposer probing files it
// does not own must not fail on the ones that are not its business.
func Section(ra io.ReaderAt, name string) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := ra.ReadAt(header, 0); err != nil {
		return nil, nil
	}
	switch {
	case string(header) == "\x7fELF":
		f, err := elf.NewFile(ra)
		if err != nil {
			return nil, nil
		}
		defer f.Close() //nolint:errcheck // read-only
		s := f.Section(name)
		if s == nil {
			return nil, nil
		}
		return sectionData(name, s)
	case header[0] == 'M' && header[1] == 'Z':
		f, err := pe.NewFile(ra)
		if err != nil {
			return nil, nil
		}
		defer f.Close() //nolint:errcheck // read-only
		s := f.Section(name)
		if s == nil {
			return nil, nil
		}
		return sectionData(name, s)
	case Magic(header):
		f, err := macho.NewFile(ra)
		if err != nil {
			return nil, nil
		}
		defer f.Close() //nolint:errcheck // read-only
		s := f.Section(name)
		if s == nil {
			return nil, nil
		}
		return sectionData(name, s)
	}
	return nil, nil
}

// sectionData reads a section's contents.
func sectionData(name string, s interface{ Data() ([]byte, error) }) ([]byte, error) {
	data, err := s.Data()
	if err != nil {
		// A section header that points past the end of the file is a
		// truncated or corrupt executable, not one of ours.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading section %s: %w", name, err)
	}
	return data, nil
}
