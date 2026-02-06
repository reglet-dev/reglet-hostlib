package template

import (
	"bytes"
	"fmt"
	"text/template"
)

// templateConfig holds configuration for the GoTemplateEngine.
type templateConfig struct {
	strict bool // Fail on missing keys
}

func defaultTemplateConfig() templateConfig {
	return templateConfig{
		strict: true, // Secure default
	}
}

// TemplateOption configures a GoTemplateEngine.
type TemplateOption func(*templateConfig)

// WithStrict enables/disables strict mode for missing keys.
// When enabled (default), template rendering fails if a referenced key is missing.
func WithStrict(enabled bool) TemplateOption {
	return func(c *templateConfig) {
		c.strict = enabled
	}
}

// GoTemplateEngine implements TemplateEngine using standard text/template.
type GoTemplateEngine struct {
	config templateConfig
}

// NewGoTemplateEngine creates a new GoTemplateEngine.
func NewGoTemplateEngine(opts ...TemplateOption) TemplateEngine {
	cfg := defaultTemplateConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &GoTemplateEngine{config: cfg}
}

// Render processes the raw manifest bytes with the provided config.
func (e *GoTemplateEngine) Render(raw []byte, config map[string]interface{}) ([]byte, error) {
	tmpl := template.New("manifest")

	// Use Option("missingkey=error") to fail fast if a key is missing.
	if e.config.strict {
		tmpl = tmpl.Option("missingkey=error")
	}

	tmpl, err := tmpl.Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest template: %w", err)
	}

	var buf bytes.Buffer
	// Wrap config in a map with "config" key to match {{.config.key}} usage in specs
	data := map[string]interface{}{
		"config": config,
	}

	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute manifest template: %w", err)
	}

	return buf.Bytes(), nil
}
