package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/flashbots/vault-auth-plugin-attest/globals"
	"github.com/flashbots/vault-auth-plugin-attest/logger"
	"go.uber.org/zap"

	tdx "github.com/google/go-tdx-guest/client"
	vaultapi "github.com/hashicorp/vault/api"
)

var (
	errTDXAttestedTokenFailedToFetch = errors.New("failed to fetch tdx-attested token")
	errTDXNonceFailedToFetch         = errors.New("failed to fetch tdx attestation nonce")
	errTDXQuoteFailedToGenerate      = errors.New("failed to generate tdx quote")
)

func (c *Client) loginTDX(
	ctx context.Context,
	td *config.TD,
) (*vaultapi.Secret, error) {
	var (
		totpTS time.Time
		nonce  [globals.TDXNonceSize]byte
		quote  []byte
		err    error
	)

	{ // fetch tdx attestation nonce
		totpCode, err := c.totpCode(td)
		if err != nil {
			return nil, err
		}
		totpTS = time.Now()

		_nonce, err := c.fetchNonce(ctx, td, totpCode)
		if err != nil {
			return nil, err
		}
		if len(_nonce) != globals.TDXNonceSize {
			return nil, fmt.Errorf("wrong size of tdx attestation nonce: expected %d; got %d",
				globals.TDXNonceSize, len(nonce),
			)
		}
		copy(nonce[:], _nonce)
	}

	{ // generate tdx quote
		quote, err = c.generateTDXQuote(ctx, nonce)
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

func (c *Client) generateTDXQuote(
	ctx context.Context,
	nonce [globals.TDXNonceSize]byte,
) ([]byte, error) {
	l := logger.FromContext(ctx)

	provider, err := tdx.GetQuoteProvider()
	if err != nil {
		return nil, err
	}

	l.Debug("Generating TDX quote")
	return tdx.GetRawQuote(provider, nonce)
}

func (c *Client) fetchTDXToken(
	ctx context.Context,
	td *config.TD,
	totpCode string,
	quote []byte,
) (*vaultapi.Secret, error) {
	l := logger.FromContext(ctx)

	path := "auth/" + td.VaultPath + "/tdx/" + td.Name + "/login"

	l.Debug("Requesting tdx attested token from vault",
		zap.String("vault_addr", c.vault.Address()),
		zap.String("vault_path", path),
	)

	return c.vault.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"totp":  totpCode,
		"quote": base64.StdEncoding.EncodeToString(quote),
	})
}
