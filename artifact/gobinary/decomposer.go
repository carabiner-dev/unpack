// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gobinary

// Para sacar del binary:
// go version -m binary

// Y sale:

// demo: go1.24.0
// 	path	github.com/carabiner-dev/unpack/demo
// 	mod	github.com/carabiner-dev/unpack	v0.0.0-20250223061039-24c56700ddfd+dirty
// 	dep	github.com/CycloneDX/cyclonedx-go	v0.9.2
// 	dep	github.com/carabiner-dev/protograph	v0.0.0-20250223042216-b2bc7a0c5cb6
// 	dep	github.com/google/go-cmp	v0.6.0
// 	dep	github.com/google/uuid	v1.6.0
// 	dep	github.com/protobom/protobom	v0.5.1
// 	dep	github.com/sirupsen/logrus	v1.9.3
// 	dep	github.com/spdx/tools-golang	v0.5.5
// 	dep	golang.org/x/sys	v0.28.0
// 	dep	google.golang.org/protobuf	v1.36.5
// 	dep	sigs.k8s.io/release-utils	v0.11.0
// 	build	-buildmode=exe
// 	build	-compiler=gc
// 	build	CGO_ENABLED=1
// 	build	CGO_CFLAGS=
// 	build	CGO_CPPFLAGS=
// 	build	CGO_CXXFLAGS=
// 	build	CGO_LDFLAGS=
// 	build	GOARCH=amd64
// 	build	GOOS=linux
// 	build	GOAMD64=v1
// 	build	vcs=git
// 	build	vcs.revision=24c56700ddfd4ad066796b3ced74b98aad722bd4
// 	build	vcs.time=2025-02-23T06:10:39Z
// 	build	vcs.modified=true

/*
 Si este lo conviertes a un go mod jala con el de source:


module	github.com/carabiner-dev/unpack/demo

go 1.24.0

require (
		github.com/CycloneDX/cyclonedx-go	v0.9.2
		github.com/carabiner-dev/protograph	v0.0.0-20250223042216-b2bc7a0c5cb6
		github.com/google/go-cmp	v0.6.0
		github.com/google/uuid	v1.6.0
		github.com/protobom/protobom	v0.5.1
		github.com/sirupsen/logrus	v1.9.3
		github.com/spdx/tools-golang	v0.5.5
		golang.org/x/sys	v0.28.0
		google.golang.org/protobuf	v1.36.5
		sigs.k8s.io/release-utils	v0.11.0
)


*/
