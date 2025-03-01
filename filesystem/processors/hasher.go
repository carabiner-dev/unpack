package processors

import (
	"fmt"
	"io"
	"io/fs"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/protobom/protobom/pkg/sbom"

	chasher "github.com/carabiner-dev/hasher"
	"github.com/carabiner-dev/unpack/filesystem/options"
)

func NewHasher() *Hasher {
	return &Hasher{
		chasher.New(),
	}
}

type Hasher struct {
	Hasher *chasher.Hasher
}

func (p *Hasher) Process(opts *options.Options, source fs.FS, node *sbom.Node) error {
	// Of we got algorithms in the options, honor them
	if len(opts.Algorithms) > 0 {
		p.Hasher.Options.Algorithms = opts.Algorithms
	}

	// Open the file
	f, err := source.Open(node.FileName)
	if err != nil {
		return fmt.Errorf("opening %q: %w", node.FileName, err)
	}
	defer f.Close()

	hashes, err := p.Hasher.HashReaders([]io.Reader{f})
	if err != nil {
		return fmt.Errorf("hashing %q: %w", node.FileName, err)
	}

	// We need to translate here
	for algo, val := range (*hashes)[0] {
		var at sbom.HashAlgorithm
		switch algo {
		case intoto.AlgorithmMD5:
			at = sbom.HashAlgorithm_MD5
		case intoto.AlgorithmSHA1:
			at = sbom.HashAlgorithm_SHA1
		case intoto.AlgorithmSHA224:
			at = sbom.HashAlgorithm_SHA224
		case intoto.AlgorithmSHA256, intoto.AlgorithmDirHash:
			at = sbom.HashAlgorithm_SHA256
		case intoto.AlgorithmSHA512:
			at = sbom.HashAlgorithm_SHA512
		case intoto.AlgorithmGitBlob, intoto.AlgorithmGitCommit, intoto.AlgorithmGitTag, intoto.AlgorithmGitTree:
			at = sbom.HashAlgorithm_SHA1
		default:
			continue
		}
		node.AddHash(at, val)
	}
	return nil
}
