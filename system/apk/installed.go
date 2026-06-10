// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package apk

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
)

// apkPackage holds the fields we extract from one stanza of the apk
// installed database. Each stanza is a sequence of single-letter "K:value"
// lines; see https://wiki.alpinelinux.org/wiki/Apk_spec for the key list.
type apkPackage struct {
	Name        string // P:
	Version     string // V:
	Arch        string // A:
	Description string // T:
	URL         string // U:
	License     string // L: SPDX expression
	Origin      string // o: source package
	Maintainer  string // m: name part
	Email       string // m: email part
	Checksum    string // C: package identity checksum, hex SHA1
	Files       []apkFile
}

// apkFile is one filesystem entry owned by a package: directories come from
// F: records (no digest), regular files from R: records with their digest
// in the following Z: record.
type apkFile struct {
	Path string
	SHA1 string // hex digest; empty for directories
}

// parseInstalled parses an apk installed database: blank-line separated
// stanzas of single-letter fields. The stanza starts with the C: checksum,
// before the P: name, so packages are built lazily from whichever field
// arrives first and flushed at the blank-line boundary. File records are
// stateful — F: sets the current directory, R: names a file inside it, and
// Z: carries the digest of the most recent R: — so files are reassembled
// while scanning.
func parseInstalled(r io.Reader) ([]*apkPackage, error) {
	var (
		pkgs []*apkPackage
		cur  *apkPackage
		dir  string
	)
	flush := func() {
		// Stanzas without a P: name are malformed; drop them.
		if cur != nil && cur.Name != "" {
			pkgs = append(pkgs, cur)
		}
		cur = nil
		dir = ""
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok || len(key) != 1 {
			continue
		}
		if cur == nil {
			cur = &apkPackage{}
		}

		switch key {
		case "P":
			cur.Name = value
		case "V":
			cur.Version = value
		case "A":
			cur.Arch = value
		case "T":
			cur.Description = value
		case "U":
			cur.URL = value
		case "L":
			cur.License = value
		case "o":
			cur.Origin = value
		case "m":
			cur.Maintainer, cur.Email = splitMaintainer(value)
		case "C":
			cur.Checksum = decodeChecksum(value)
		case "F":
			dir = value
			cur.Files = append(cur.Files, apkFile{Path: "/" + value})
		case "R":
			cur.Files = append(cur.Files, apkFile{Path: "/" + dir + "/" + value})
		case "Z":
			// Digest of the most recent R: record.
			if len(cur.Files) > 0 && cur.Files[len(cur.Files)-1].SHA1 == "" {
				cur.Files[len(cur.Files)-1].SHA1 = decodeChecksum(value)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()
	return pkgs, nil
}

// decodeChecksum converts an apk "Q1"-prefixed checksum (base64-encoded
// SHA1) to its hex form. Unknown encodings are returned empty rather than
// mislabeled.
func decodeChecksum(v string) string {
	if !strings.HasPrefix(v, "Q1") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, "Q1"))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

// splitMaintainer splits the RFC822-style "Name <email>" maintainer field.
// When no angle brackets are present the whole value is returned as the name.
func splitMaintainer(s string) (name, email string) {
	name, rest, found := strings.Cut(s, "<")
	name = strings.TrimSpace(name)
	if !found {
		return name, ""
	}
	return name, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ">"))
}
