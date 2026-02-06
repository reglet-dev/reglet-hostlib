package host

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewExecutor(t *testing.T) {
	ctx := context.Background()
	e, err := NewExecutor(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, e)
	if e != nil {
		err := e.Close(ctx)
		assert.NoError(t, err)
	}
}
