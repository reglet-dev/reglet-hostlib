package parser

import (
	"encoding/json"

	abi "github.com/reglet-dev/reglet-abi"
)

// JSONManifestParser implements ManifestParser for JSON.
type JSONManifestParser struct{}

// NewJSONManifestParser creates a new JSONManifestParser.
func NewJSONManifestParser() ManifestParser {
	return &JSONManifestParser{}
}

// Parse unmarshals JSON bytes into a Manifest struct.
func (p *JSONManifestParser) Parse(data []byte) (*abi.Manifest, error) {
	var manifest abi.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}
