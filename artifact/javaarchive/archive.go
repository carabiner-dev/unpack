// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package javaarchive

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // an identifier repositories index jars by, not a defence
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path"
	"sort"
	"strings"
)

// This file reads a Java archive: who it says it is, and the other
// archives and packages inside it.
//
// An archive names itself in two places. Maven writes, for every
// artifact it builds, a pom.properties with its coordinates; and any
// build tool may fill in the manifest with a title, a version and a
// vendor. Dependencies are bundled in two ways: as whole archives inside
// the archive, which is what a WAR, an EAR and a Spring Boot jar do, or
// unpacked into it, as a shaded jar does, in which case the
// pom.properties of each remains.

// Limits that keep a hostile or broken archive from exhausting memory.
const (
	// maxDepth is how deep archives are read inside archives. An EAR
	// holds WARs that hold jars: three.
	maxDepth = 4

	// maxNestedSize is the size of the largest nested archive read. It
	// has to be held in memory to be opened.
	maxNestedSize = 256 << 20

	// maxMetadataSize is the size of the largest manifest or
	// pom.properties read.
	maxMetadataSize = 1 << 20
)

// metaInf is the directory of an archive that holds what it says of
// itself.
const metaInf = "META-INF"

// Sources of an archive's identity, surest first.
const (
	SourcePOM      = "pom.properties"
	SourceManifest = "manifest"
	SourceFileName = "filename"
)

// Identity is who an archive, or a package unpacked into one, is.
type Identity struct {
	// Group is the Maven group, known only from a pom.properties.
	Group   string
	Name    string
	Version string

	// Vendor is who the manifest says the archive is from, or failing
	// that the organization its POM names.
	Vendor string

	// Licenses are the licenses it states, as SPDX identifiers where
	// they are recognized, and LicenseSource where they were read:
	// pom.xml, manifest or license-file.
	Licenses      []string
	LicenseSource string

	// Source says where the identity was read from.
	Source string
}

// Archive is a Java archive as read.
type Archive struct {
	Identity Identity

	// Path is where the archive is inside the one that holds it, and
	// empty for the outermost.
	Path string

	// SHA256 and SHA1 are the hashes of a nested archive's file, in
	// hexadecimal. The outermost has none here: whoever opened it has
	// its bytes.
	SHA256 string
	SHA1   string

	// MainClass is the class the manifest names to run.
	MainClass string

	// Shaded are the packages unpacked into the archive: the
	// pom.properties it holds that are not its own.
	Shaded []Identity

	// Nested are the archives inside it.
	Nested []*Archive

	// Skipped are the nested archives that were not read, each with why.
	Skipped []string
}

// extensions are the suffixes of Java archives: plain, web and
// enterprise ones, resource adapters, service archives, and the plugins
// of Jenkins, which are jars by other names.
var extensions = []string{".jar", ".war", ".ear", ".rar", ".sar", ".par", ".hpi", ".jpi"}

// IsArchiveName says whether a file name is a Java archive's.
func IsArchiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, extension := range extensions {
		if strings.HasSuffix(lower, extension) {
			return true
		}
	}
	return false
}

// readArchive reads an opened archive. name is its file name, which
// settles who it is when it holds the properties of several packages or
// of none.
func readArchive(zr *zip.Reader, name string, depth int) *Archive {
	archive := &Archive{}
	var manifest map[string]string
	poms := []Identity{}

	// What the embedded POMs declare, by the directory Maven puts each
	// in, and the texts of the archive's license files.
	type declared struct {
		licenses     []string
		organization string
	}
	declarations := map[string]declared{}
	licenseTexts := [][]byte{}

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		switch {
		case f.Name == metaInf+"/MANIFEST.MF":
			if data, ok := readEntry(f, maxMetadataSize); ok {
				manifest = parseManifest(data)
			}
		case isPOMXML(f.Name):
			if data, ok := readEntry(f, maxMetadataSize); ok {
				parts := strings.Split(f.Name, "/")
				licenses, organization := pomDeclares(data)
				declarations[pomKey(parts[2], parts[3])] = declared{licenses, organization}
			}
		case isLicenseEntry(f.Name):
			if data, ok := readEntry(f, maxLicenseFileSize); ok {
				licenseTexts = append(licenseTexts, data)
			}
		case isPOMProperties(f.Name):
			if data, ok := readEntry(f, maxMetadataSize); ok {
				if id, ok := pomIdentity(data); ok {
					poms = append(poms, id)
				}
			}
		case IsArchiveName(f.Name):
			nested, why := readNested(f, depth)
			if nested != nil {
				archive.Nested = append(archive.Nested, nested)
			} else if why != "" {
				archive.Skipped = append(archive.Skipped, f.Name+": "+why)
			}
		}
	}

	// What a POM declares goes to the package it is of.
	apply := func(id *Identity) {
		declaration := declarations[pomKey(id.Group, id.Name)]
		if len(declaration.licenses) > 0 {
			id.Licenses, id.LicenseSource = declaration.licenses, LicenseFromPOM
		}
		if id.Vendor == "" {
			id.Vendor = declaration.organization
		}
	}

	archive.MainClass = manifest["main-class"]
	own, shaded := ownIdentity(poms, name)
	archive.Shaded = shaded
	for i := range archive.Shaded {
		apply(&archive.Shaded[i])
	}
	switch {
	case own != nil:
		archive.Identity = *own
		archive.Identity.Vendor = manifestVendor(manifest)
		apply(&archive.Identity)
	default:
		archive.Identity = manifestIdentity(manifest, name)
	}

	// The manifest and the license file speak for the archive itself.
	// In an archive other packages were unpacked into, the license file
	// may be any of theirs, so it is not read there.
	if own := &archive.Identity; len(own.Licenses) == 0 {
		if licenses := bundleLicenses(manifest["bundle-license"]); len(licenses) > 0 {
			own.Licenses, own.LicenseSource = licenses, LicenseFromManifest
		} else if licenses := fileLicense(licenseTexts); len(licenses) > 0 && len(archive.Shaded) == 0 {
			own.Licenses, own.LicenseSource = licenses, LicenseFromFile
		}
	}

	sort.Slice(archive.Shaded, func(i, j int) bool { return coordinate(&archive.Shaded[i]) < coordinate(&archive.Shaded[j]) })
	sort.Slice(archive.Nested, func(i, j int) bool { return archive.Nested[i].Path < archive.Nested[j].Path })
	return archive
}

func coordinate(id *Identity) string { return id.Group + ":" + id.Name + ":" + id.Version }

// isPOMProperties says whether an entry is the properties Maven writes
// for an artifact: META-INF/maven/<group>/<artifact>/pom.properties.
func isPOMProperties(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 5 && parts[0] == metaInf && parts[1] == "maven" && parts[4] == "pom.properties"
}

// readEntry reads an entry of an archive, up to a size, and says whether
// it was read whole.
func readEntry(f *zip.File, limit uint64) ([]byte, bool) {
	if f.UncompressedSize64 > limit {
		return nil, false
	}
	rc, err := f.Open()
	if err != nil {
		return nil, false
	}
	defer rc.Close() //nolint:errcheck // read-only
	// The size an entry states is its own word; what is read is capped
	// whatever it says.
	data, err := io.ReadAll(io.LimitReader(rc, int64(limit)+1)) //nolint:gosec // the limits are small constants
	if err != nil || uint64(len(data)) > limit {
		return nil, false
	}
	return data, true
}

// readNested reads an archive inside an archive. It returns nothing and
// a reason when it is not read, and nothing and no reason when the entry
// is no archive after all.
func readNested(f *zip.File, depth int) (nested *Archive, why string) {
	if depth+1 >= maxDepth {
		return nil, "nested too deep"
	}
	data, ok := readEntry(f, maxNestedSize)
	if !ok {
		return nil, "too large to read, or unreadable"
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, ""
	}
	nested = readArchive(zr, path.Base(f.Name), depth+1)
	nested.Path = f.Name
	sum256 := sha256.Sum256(data)
	sum1 := sha1.Sum(data) //nolint:gosec // see the import
	nested.SHA256, nested.SHA1 = hex.EncodeToString(sum256[:]), hex.EncodeToString(sum1[:])
	return nested, ""
}

// parseManifest reads the main section of a manifest: attributes as
// "Name: value", a line starting with a space carrying on the one
// before, up to the first empty line. Names are returned in lower case,
// as they are not told apart by case.
func parseManifest(data []byte) map[string]string {
	attributes := map[string]string{}
	last := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), maxMetadataSize)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") {
			if last != "" {
				attributes[last] += line[1:]
			}
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		last = strings.ToLower(strings.TrimSpace(name))
		attributes[last] = strings.TrimSpace(value)
	}
	return attributes
}

// pomIdentity reads the coordinates of a pom.properties.
func pomIdentity(data []byte) (Identity, bool) {
	properties := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		properties[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	id := Identity{
		Group: properties["groupId"], Name: properties["artifactId"], Version: properties["version"],
		Source: SourcePOM,
	}
	return id, id.Group != "" && id.Name != "" && id.Version != ""
}

// ownIdentity picks, of the pom.properties an archive holds, the one
// that is its own, and returns the rest as what was unpacked into it.
//
// A lone one is the archive's. Of several, it is the one the file is
// named after, the longest such when a name fits more than one; and when
// the file is named after none, none is its own: a shaded jar is often
// named for what it is and not for the artifact that built it.
func ownIdentity(poms []Identity, name string) (own *Identity, shaded []Identity) {
	if len(poms) == 0 {
		return nil, nil
	}
	if len(poms) == 1 {
		return &poms[0], nil
	}
	base := baseName(name)
	best := -1
	for i := range poms {
		artifact := poms[i].Name
		if base != artifact && !strings.HasPrefix(base, artifact+"-") {
			continue
		}
		if best < 0 || len(artifact) > len(poms[best].Name) {
			best = i
		}
	}
	for i := range poms {
		if i != best {
			shaded = append(shaded, poms[i])
		}
	}
	if best < 0 {
		return nil, shaded
	}
	return &poms[best], shaded
}

// baseName is a file name without its directory and its extension.
func baseName(name string) string {
	base := path.Base(strings.ReplaceAll(name, `\`, "/"))
	if dot := strings.LastIndex(base, "."); dot > 0 {
		base = base[:dot]
	}
	return base
}

func manifestVendor(manifest map[string]string) string {
	for _, attribute := range []string{"implementation-vendor", "bundle-vendor", "specification-vendor"} {
		if vendor := manifest[attribute]; vendor != "" {
			return vendor
		}
	}
	return ""
}

// manifestIdentity reads who an archive is from its manifest: an OSGi
// bundle by its symbolic name and version, any other archive by its
// module name or implementation title and its implementation version.
// An archive whose manifest names it nowhere is known by its file name
// alone, which states no version that can be told from the name for
// sure.
func manifestIdentity(manifest map[string]string, name string) Identity {
	id := Identity{Vendor: manifestVendor(manifest), Source: SourceManifest}

	// A symbolic name may be followed by directives, ";singleton:=true".
	symbolic, _, _ := strings.Cut(manifest["bundle-symbolicname"], ";")
	for _, candidate := range []string{strings.TrimSpace(symbolic), manifest["automatic-module-name"], manifest["implementation-title"]} {
		if candidate != "" {
			id.Name = candidate
			break
		}
	}
	for _, attribute := range []string{"bundle-version", "implementation-version"} {
		if version := manifest[attribute]; version != "" {
			id.Version = version
			break
		}
	}
	if id.Name == "" {
		return Identity{Name: baseName(name), Vendor: id.Vendor, Source: SourceFileName}
	}
	return id
}
