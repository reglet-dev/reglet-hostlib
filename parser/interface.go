package parser

import abi "github.com/reglet-dev/reglet-abi"

// ManifestParser parses raw manifest bytes into a Manifest.
type ManifestParser interface {
	// Parse unmarshals manifest bytes into a Manifest struct.
	Parse(data []byte) (*abi.Manifest, error)
}
