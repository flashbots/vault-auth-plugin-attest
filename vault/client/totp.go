package client

import (
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/pquerna/otp/totp"
)

func (c *Client) totpCode(td *config.TD) (string, error) {
	return totp.GenerateCodeCustom(
		td.TOTPSecret,
		time.Now().UTC(),
		c.totpOptions,
	)
}
