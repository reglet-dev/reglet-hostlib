package template

// TemplateEngine renders templates with provided data.
type TemplateEngine interface {
	// Render processes raw bytes as a template using the provided configuration.
	Render(raw []byte, config map[string]interface{}) ([]byte, error)
}
