// OWNERSHIP: REGLET RUNTIME (should NOT be in SDK)
// STATUS: Needs migration to reglet/internal/infrastructure/parser/

// Package parser provides functionality for parsing plugin manifests.
package parser

import (
	abi "github.com/reglet-dev/reglet-abi"
	"gopkg.in/yaml.v3"
)

// YamlManifestParser implements ManifestParser for YAML.
type YamlManifestParser struct{}

// NewYamlManifestParser creates a new YamlManifestParser.
func NewYamlManifestParser() ManifestParser {
	return &YamlManifestParser{}
}

// Parse unmarshals YAML bytes into a Manifest struct.
func (p *YamlManifestParser) Parse(data []byte) (*abi.Manifest, error) {
	var manifest abi.Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}
