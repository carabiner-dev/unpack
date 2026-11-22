// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gradle

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VerificationFile is where a build keeps the checksums Gradle verifies
// its dependencies against, relative to the root of the build.
const VerificationFile = "gradle/verification-metadata.xml"

// Verification is a verification-metadata.xml: for the modules a build
// verifies, the checksums of their files.
type Verification struct {
	// checksums holds, by "group:name:version" and then by file name,
	// the checksums of the file by algorithm name.
	checksums map[string]map[string]map[string]string
}

type rawVerification struct {
	Components []struct {
		Group     string `xml:"group,attr"`
		Name      string `xml:"name,attr"`
		Version   string `xml:"version,attr"`
		Artifacts []struct {
			Name      string `xml:"name,attr"`
			Checksums []struct {
				XMLName xml.Name `xml:""`
				Value   string   `xml:"value,attr"`
			} `xml:",any"`
		} `xml:"artifact"`
	} `xml:"components>component"`
}

// checksumElements are the elements of an artifact that state a checksum
// of its file. The others, a signing key among them, are not checksums.
var checksumElements = map[string]bool{"md5": true, "sha1": true, "sha256": true, "sha512": true}

// ReadVerification reads a verification-metadata.xml.
func ReadVerification(path string) (*Verification, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading verification metadata: %w", err)
	}
	return ParseVerification(data)
}

// ParseVerification reads the contents of a verification-metadata.xml.
func ParseVerification(data []byte) (*Verification, error) {
	raw := &rawVerification{}
	if err := xml.Unmarshal(data, raw); err != nil {
		return nil, fmt.Errorf("parsing verification metadata: %w", err)
	}
	verification := &Verification{checksums: map[string]map[string]map[string]string{}}
	for i := range raw.Components {
		component := &raw.Components[i]
		key := component.Group + ":" + component.Name + ":" + component.Version
		for j := range component.Artifacts {
			artifact := &component.Artifacts[j]
			for _, checksum := range artifact.Checksums {
				algorithm := strings.ToLower(checksum.XMLName.Local)
				value := strings.ToLower(strings.TrimSpace(checksum.Value))
				if !checksumElements[algorithm] || value == "" {
					continue
				}
				if verification.checksums[key] == nil {
					verification.checksums[key] = map[string]map[string]string{}
				}
				if verification.checksums[key][artifact.Name] == nil {
					verification.checksums[key][artifact.Name] = map[string]string{}
				}
				verification.checksums[key][artifact.Name][algorithm] = value
			}
		}
	}
	return verification, nil
}

// packagings are the files a module's library may be, the likeliest
// first.
var packagings = []string{".jar", ".aar"}

// Library returns the checksums of the library of a module, by algorithm
// name, and the name of its file: the module's jar, or the aar of an
// Android library. A module is verified file by file, its POM and its
// Gradle metadata as well as its library, and only the library is what
// the project is built from.
func (v *Verification) Library(module *Module) (checksums map[string]string, file string) {
	if v == nil {
		return nil, ""
	}
	files := v.checksums[module.Group+":"+module.Name+":"+module.Version]
	for _, packaging := range packagings {
		name := module.Name + "-" + module.Version + packaging
		if found, ok := files[name]; ok {
			return found, name
		}
	}
	return nil, ""
}

// FindVerification looks for the verification metadata of the build a
// directory is part of: at the directory, then at those above it, as a
// project of a build is below its root. It stops at the root of the git
// repository, and returns nothing when there is none.
func FindVerification(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(abs, filepath.FromSlash(VerificationFile))
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		if _, err := os.Lstat(filepath.Join(abs, ".git")); err == nil {
			return ""
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return ""
		}
		abs = parent
	}
}
