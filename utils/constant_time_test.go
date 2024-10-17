package utils_test

import (
	"testing"

	"github.com/flashbots/vault-auth-plugin-attest/utils"
	"github.com/stretchr/testify/assert"
)

func TestConstantTimeMask(t *testing.T) {
	{
		x := []byte{0xFF}
		y := []byte{0xFF, 0xFF}
		assert.Equal(t,
			0,
			utils.ConstantTimeMask(x, y),
		)
	}
	{
		x := []byte{0x00, 0x00, 0x00, 0x00}
		y := []byte{0x00, 0x00, 0x00, 0x00}
		assert.Equal(t,
			0,
			utils.ConstantTimeMask(x, y),
		)
	}
	{
		x := []byte{0x00, 0xFF, 0x00, 0x00}
		y := []byte{0x00, 0x01, 0x00, 0x00}
		assert.Equal(t,
			1,
			utils.ConstantTimeMask(x, y),
		)
	}
	{
		x := []byte{0xFF, 0xFE, 0xFF, 0xFF}
		y := []byte{0x00, 0x01, 0x00, 0x00}
		assert.Equal(t,
			0,
			utils.ConstantTimeMask(x, y),
		)
	}
}
