package parser

import abi "github.com/reglet-dev/reglet-abi"

// ManifestParser parses raw YAML bytes into a PluginManifest.
type ManifestParser interface {
	// Parse unmarshals YAML bytes into a PluginManifest struct.
	Parse(data []byte) (*abi.Manifest, error)
}
