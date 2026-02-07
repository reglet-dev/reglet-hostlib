package template_test

import (
	"testing"

	"github.com/reglet-dev/reglet-host-sdk/template"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoTemplateEngine_Render(t *testing.T) {
	engine := template.NewGoTemplateEngine()

	t.Run("Successful Resolution", func(t *testing.T) {
		raw := []byte(`name: "{{.config.name}}"` + "\n" + `version: "1.0.0"`)
		config := map[string]interface{}{
			"name": "resolved-plugin",
		}

		out, err := engine.Render(raw, config)
		require.NoError(t, err)
		assert.Contains(t, string(out), `name: "resolved-plugin"`)
	})

	t.Run("Missing Key Fails", func(t *testing.T) {
		raw := []byte(`name: "{{.config.missing}}"`)
		config := map[string]interface{}{
			"name": "something",
		}

		_, err := engine.Render(raw, config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "map has no entry for key")
	})

	t.Run("Invalid Template Syntax", func(t *testing.T) {
		raw := []byte(`name: "{{.config.name"`)
		config := map[string]interface{}{
			"name": "something",
		}

		_, err := engine.Render(raw, config)
		require.Error(t, err)
	})
}
