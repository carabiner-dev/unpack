// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package stitch enriches dependency graphs with supplemental bills of
// materials. A catalog indexes the components the supplements describe by
// hash and purl; the stitcher matches every node of an extraction against
// it and grafts each describing supplement onto the node, merged into it
// or hung below it, using protobom's graft, absorb and dedupe operations.
package stitch
