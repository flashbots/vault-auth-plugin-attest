package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/flashbots/vault-auth-plugin-attest/logger"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

func (c *Client) totpCode(td *config.TD) (string, error) {
	return totp.GenerateCodeCustom(
		td.TOTPSecret,
		time.Now().UTC(),
		c.totpOptions,
	)
}

func (c *Client) fetchNonce(
	ctx context.Context,
	td *config.TD,
	totpCode string,
) ([]byte, error) {
	l := logger.FromContext(ctx)

	path := fmt.Sprintf("auth/%s/%s/%s/nonce",
		td.VaultPath,
		td.AttestationType,
		td.Name,
	)

	l.Debug("Requesting attestation nonce from vault",
		zap.String("vault_addr", c.vault.Address()),
		zap.String("vault_path", path),
	)

	res, err := c.vault.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"totp": totpCode,
	})
	if err != nil {
		return nil, err
	}

	_nonceBase64, exists := res.Data["nonce"]
	if !exists {
		return nil, errors.New("no attestation nonce was returned")
	}
	nonceBase64, ok := _nonceBase64.(string)
	if !ok {
		return nil, errors.New("attestation nonce must be a base64 sting")
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode attestation nonce: %w", err)
	}

	return nonce, nil
}
