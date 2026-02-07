package dto

import "github.com/reglet-dev/reglet-host-sdk/plugin/values"

// PluginSpecDTO represents a plugin specification from configuration.
type PluginSpecDTO struct {
	Name   string
	Digest string
}

func (s *PluginSpecDTO) ToPluginReference() (values.PluginReference, error) {
	return values.ParsePluginReference(s.Name)
}

func (s *PluginSpecDTO) ToDigest() (values.Digest, error) {
	if s.Digest == "" {
		return values.Digest{}, nil
	}
	return values.ParseDigest(s.Digest)
}
