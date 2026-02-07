package extractor

import (
	"fmt"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-host-sdk/parser"
	"github.com/reglet-dev/reglet-host-sdk/template"
)

// ManifestExtractor extracts capabilities from a plugin manifest.
type ManifestExtractor struct {
	parser   parser.ManifestParser
	renderer template.TemplateEngine
	manifest []byte
}

// ManifestExtractorOption configures the ManifestExtractor.
type ManifestExtractorOption func(*ManifestExtractor)

// WithParser sets the manifest parser.
func WithParser(p parser.ManifestParser) ManifestExtractorOption {
	return func(e *ManifestExtractor) {
		e.parser = p
	}
}

// WithTemplateEngine sets the template engine.
func WithTemplateEngine(t template.TemplateEngine) ManifestExtractorOption {
	return func(e *ManifestExtractor) {
		e.renderer = t
	}
}

// NewManifestExtractor creates a new ManifestExtractor for the given manifest.
func NewManifestExtractor(manifest []byte, opts ...ManifestExtractorOption) *ManifestExtractor {
	e := &ManifestExtractor{
		manifest: manifest,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Extract analyzes the manifest and returns the required capabilities.
func (e *ManifestExtractor) Extract(config map[string]interface{}) (*hostfunc.GrantSet, error) {
	if e.parser == nil {
		return nil, fmt.Errorf("manifest parser is required")
	}

	data := e.manifest
	if e.renderer != nil {
		var err error
		data, err = e.renderer.Render(data, config)
		if err != nil {
			return nil, fmt.Errorf("failed to render manifest: %w", err)
		}
	}

	manifest, err := e.parser.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Direct return of the GrantSet pointer
	return &manifest.Capabilities, nil
}
