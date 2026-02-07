package dto

import (
	"io"

	"github.com/reglet-dev/reglet-host-sdk/plugin/entities"
)

// PluginArtifactDTO is a data transfer object for plugin artifacts.
type PluginArtifactDTO struct {
	Plugin *entities.Plugin
	WASM   io.ReadCloser
}

func NewPluginArtifactDTO(plugin *entities.Plugin, wasm io.ReadCloser) *PluginArtifactDTO {
	return &PluginArtifactDTO{
		Plugin: plugin,
		WASM:   wasm,
	}
}

func (d *PluginArtifactDTO) Close() error {
	if d.WASM != nil {
		return d.WASM.Close()
	}
	return nil
}
