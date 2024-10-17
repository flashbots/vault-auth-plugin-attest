package plugin

import (
	"crypto/rand"
	"io"

	"github.com/hashicorp/go-kms-wrapping/entropy/v2"
)

func (b *backend) Rand() io.Reader {
	if src, ok := b.System().(entropy.Sourcer); ok {
		return entropy.NewReader(src)
	}
	return rand.Reader
}
