package types_test

import (
	"encoding/json"
	"testing"

	"github.com/flashbots/vault-auth-plugin-attest/types"
	"github.com/stretchr/testify/assert"
)

func TestByesJson(t *testing.T) {
	{
		b := types.Bytes{0x00, 0x01, 0x02}
		j, err := json.Marshal(b)
		assert.NoError(t, err)
		assert.Equal(t, `"AAEC"`, string(j))
	}

	{
		b := types.Bytes{}
		s := `"AAECAAEC"`
		err := json.Unmarshal([]byte(s), &b)
		assert.NoError(t, err)
		assert.Equal(t, len(b), 6)
		assert.Equal(t, uint8(0x00), b[0])
		assert.Equal(t, uint8(0x01), b[1])
		assert.Equal(t, uint8(0x02), b[2])
		assert.Equal(t, uint8(0x00), b[3])
		assert.Equal(t, uint8(0x01), b[4])
		assert.Equal(t, uint8(0x02), b[5])
		s = `"AAEC"`
		err = json.Unmarshal([]byte(s), &b)
		assert.NoError(t, err)
		assert.Equal(t, len(b), 3)
		assert.Equal(t, uint8(0x00), b[0])
		assert.Equal(t, uint8(0x01), b[1])
		assert.Equal(t, uint8(0x02), b[2])
	}
}
