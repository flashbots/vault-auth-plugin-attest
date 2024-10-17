package types_test

import (
	"encoding/json"
	"testing"

	"github.com/flashbots/vault-auth-plugin-attest/types"
	"github.com/stretchr/testify/assert"
)

func TestByte48Json(t *testing.T) {
	{
		b48 := types.Byte48{}
		j, err := json.Marshal(b48)
		assert.NoError(t, err)
		assert.Equal(t, `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, string(j))
	}

	{
		b48 := types.Byte48{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		}
		j, err := json.Marshal(b48)
		assert.NoError(t, err)
		assert.Equal(t, `"AAECAwQFBgcICQoLAAECAwQFBgcICQoLAAECAwQFBgcICQoLAAECAwQFBgcICQoL"`, string(j))
		var b48bis types.Byte48
		err = json.Unmarshal(j, &b48bis)
		assert.NoError(t, err)
		assert.Equal(t, b48, b48bis)
	}
}
