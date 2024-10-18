package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/flashbots/vault-auth-plugin-attest/globals"
	"github.com/flashbots/vault-auth-plugin-attest/utils"
	"go.uber.org/zap"

	tdx "github.com/google/go-tdx-guest/client"
	vaultapi "github.com/hashicorp/vault/api"
)

var (
	errTDXAttestedTokenFailedToFetch = errors.New("failed to fetch tdx-attested token")
	errTDXNonceFailedToFetch         = errors.New("failed to fetch tdx attestation nonce")
	errTDXQuoteFailedToGenerate      = errors.New("failed to generate tdx quote")
)

func (c *Client) loginTDX(ctx context.Context, td *config.TD) (*vaultapi.Secret, error) {
	var (
		totpTS time.Time
		nonce  [64]byte
		quote  []byte
		err    error
	)

	{ // fetch tdx attestation nonce
		totpCode, err := c.totpCode(td)
		if err != nil {
			return nil, err
		}
		totpTS = time.Now()

		nonce, err = c.fetchTDXNonce(ctx, td, totpCode)
		if err != nil {
			return nil, err
		}
	}

	{ // generate tdx quote
		quote, err = c.generateTDXQuote(nonce)
		if err != nil {
			return nil, err
		}
	}

	{ // fetch tdx attested token
		time.Sleep(time.Until(totpTS.Add(globals.TOTPPeriod))) // wait for next totp
		totpCode, err := c.totpCode(td)
		if err != nil {
			return nil, err
		}

		return c.fetchTDXToken(ctx, td, totpCode, quote)
	}
}

func (c *Client) fetchTDXNonce(
	ctx context.Context,
	td *config.TD,
	totpCode string,
) ([64]byte, error) {
	return utils.WrapError(fmt.Errorf("%w: %s", errTDXNonceFailedToFetch, td.Name), func() ([64]byte, error) {
		l := zap.L()

		path := "auth/" + td.VaultPath + "/tdx/" + td.Name + "/nonce"

		l.Debug("Requesting tdx attestation nonce from vault",
			zap.String("vault_addr", c.vault.Address()),
			zap.String("vault_path", path),
		)

		res, err := c.vault.Logical().WriteWithContext(ctx, path, map[string]interface{}{
			"totp": totpCode,
		})
		if err != nil {
			return [64]byte{}, err
		}

		_nonceBase64, exists := res.Data["nonce"]
		if !exists {
			return [64]byte{}, errors.New("no tdx attestation nonce was returned")
		}
		nonceBase64, ok := _nonceBase64.(string)
		if !ok {
			return [64]byte{}, errors.New("tdx attestation nonce must be a base64 sting")
		}

		nonce, err := base64.StdEncoding.DecodeString(nonceBase64)
		if err != nil {
			return [64]byte{}, fmt.Errorf("failed to base64-decode tdx attestation nonce: %w", err)
		}

		if len(nonce) != 64 {
			return [64]byte{}, fmt.Errorf("tdx attestation nonce is not 64 bytes long: actual length is %d bytes", len(nonce))
		}

		return [64]byte(nonce), nil
	})
}

func (c *Client) generateTDXQuote(nonce [64]byte) ([]byte, error) {
	return utils.WrapError(errTDXQuoteFailedToGenerate, func() ([]byte, error) {
		l := zap.L()

		l.Debug("Generating TDX quote")

		provider, err := tdx.GetQuoteProvider()
		if err != nil {
			return nil, err
		}

		return tdx.GetRawQuote(provider, nonce)
	})
}

func (c *Client) fetchTDXToken(
	ctx context.Context,
	td *config.TD,
	totpCode string,
	quote []byte,
) (*vaultapi.Secret, error) {
	return utils.WrapError(errTDXAttestedTokenFailedToFetch, func() (*vaultapi.Secret, error) {
		l := zap.L()

		path := "auth/" + td.VaultPath + "/tdx/" + td.Name + "/login"

		l.Debug("Requesting tdx attested token from vault",
			zap.String("vault_addr", c.vault.Address()),
			zap.String("vault_path", path),
		)

		return c.vault.Logical().WriteWithContext(ctx, path, map[string]interface{}{
			"totp":  totpCode,
			"quote": base64.StdEncoding.EncodeToString(quote),
		})
	})
}
