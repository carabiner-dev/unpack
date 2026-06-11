// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package rpm

import (
	"github.com/google/uuid"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/protobom/protobom/pkg/sbom"
)

// The RPM database stores POSIX mode bits in FileModes; these pick out the
// file-type field (S_IFMT) and the directory type (S_IFDIR) without
// depending on host-OS syscall constants.
const (
	modeTypeMask uint16 = 0o170000
	modeDir      uint16 = 0o040000
)

// addPackageFiles expands the file list owned by p and relates each file to
// the package node via a "contains" edge. The RPM database stores the file
// list split across three parallel arrays — BaseNames (filename), DirIndexes
// (index into DirNames), and DirNames (directory) — and per-file metadata in
// the FileDigests/FileSizes slices. Reassembling the full path is a join of
// DirNames[DirIndexes[i]] + BaseNames[i].
//
// Directories owned by the package are skipped — the file list captures the
// package's content, not the tree structure. Other entries without a digest
// (symlinks, special files) are still emitted, just without a Hashes field.
func addPackageFiles(nl *sbom.NodeList, p *rpmdb.PackageInfo, packageID string) error {
	if len(p.BaseNames) == 0 {
		return nil
	}
	algo, hasAlgo := mapDigestAlgorithm(p.DigestAlgorithm)
	for i, base := range p.BaseNames {
		if i < len(p.FileModes) && p.FileModes[i]&modeTypeMask == modeDir {
			continue
		}
		dir := ""
		if i < len(p.DirIndexes) {
			idx := int(p.DirIndexes[i])
			if idx >= 0 && idx < len(p.DirNames) {
				dir = p.DirNames[idx]
			}
		}
		path := dir + base

		node := &sbom.Node{
			Id:       uuid.NewString(),
			Type:     sbom.Node_FILE,
			Name:     path,
			FileName: path,
		}
		if hasAlgo && i < len(p.FileDigests) && p.FileDigests[i] != "" {
			node.Hashes = map[int32]string{
				int32(algo): p.FileDigests[i],
			}
		}
		if err := nl.RelateNodeAtID(node, packageID, sbom.Edge_contains); err != nil {
			return err
		}
	}
	return nil
}

// mapDigestAlgorithm maps the RPM/PGP hash algorithm enum to protobom's. The
// boolean is false for algorithms protobom doesn't model (RIPEMD160,
// TIGER192, HAVAL); for those we just drop the digest rather than mislabel
// it.
//
// The RPM enum values come from rpmio/rpmpgp.h:
// https://github.com/rpm-software-management/rpm/blob/0b75075a/rpmio/rpmpgp.h#L241-L275
func mapDigestAlgorithm(d rpmdb.DigestAlgorithm) (sbom.HashAlgorithm, bool) {
	switch d {
	case rpmdb.PGPHASHALGO_MD5:
		return sbom.HashAlgorithm_MD5, true
	case rpmdb.PGPHASHALGO_SHA1:
		return sbom.HashAlgorithm_SHA1, true
	case rpmdb.PGPHASHALGO_MD2:
		return sbom.HashAlgorithm_MD2, true
	case rpmdb.PGPHASHALGO_SHA256:
		return sbom.HashAlgorithm_SHA256, true
	case rpmdb.PGPHASHALGO_SHA384:
		return sbom.HashAlgorithm_SHA384, true
	case rpmdb.PGPHASHALGO_SHA512:
		return sbom.HashAlgorithm_SHA512, true
	case rpmdb.PGPHASHALGO_SHA224:
		return sbom.HashAlgorithm_SHA224, true
	}
	return sbom.HashAlgorithm_UNKNOWN, false
}
