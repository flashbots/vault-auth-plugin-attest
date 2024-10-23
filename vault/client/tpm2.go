package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/flashbots/vault-auth-plugin-attest/globals"
	"github.com/flashbots/vault-auth-plugin-attest/logger"
	"github.com/google/go-attestation/attest"
	vaultapi "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func (c *Client) loginTPM2(
	ctx context.Context,
	td *config.TD,
) (*vaultapi.Secret, error) {
	var (
		totpTS      time.Time
		nonce       = make([]byte, globals.TPM2NonceSize)
		attestation *attest.PlatformParameters
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
		if len(_nonce) != globals.TPM2NonceSize {
			return nil, fmt.Errorf("wrong size of tdx attestation nonce: expected %d; got %d",
				globals.TPM2NonceSize, len(_nonce),
			)
		}
		copy(nonce, _nonce)
	}

	{ // generate tpm2 attestation
		akBlob, err := base64.StdEncoding.DecodeString(td.TPM2AKPrivateBlob)
		if err != nil {
			return nil, fmt.Errorf("failed to base64-decode blob of tpm2 private attestation key: %w",
				err,
			)
		}

		attestation, err = c.generateTPM2Attestation(ctx, akBlob, nonce)
		if err != nil {
			return nil, err
		}
	}

	{ // fetch tpm2 attested token
		time.Sleep(time.Until(totpTS.Add(globals.TOTPPeriod))) // wait for next totp
		totpCode, err := c.totpCode(td)
		if err != nil {
			return nil, err
		}

		return c.fetchTPM2Token(ctx, td, totpCode, attestation, nonce)
	}
}

func (c *Client) generateTPM2Attestation(
	ctx context.Context,
	akBlob []byte,
	nonce []byte,
) (*attest.PlatformParameters, error) {
	l := logger.FromContext(ctx)

	l.Debug("Opening TPM2 device")

	provider, err := attest.OpenTPM(&attest.OpenConfig{})
	if err != nil {
		return nil, fmt.Errorf("failed to open tpm2 device: %w",
			err,
		)
	}
	defer func() {
		l.Debug("Closing TPM2 device")
		provider.Close()
	}()

	if provider.Version() != attest.TPMVersion20 {
		return nil, fmt.Errorf("invalid tpm version: expected %d; got %d",
			attest.TPMVersion20, provider.Version(),
		)
	}

	l.Debug("Loading attestation key")

	ak, err := provider.LoadAK(akBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to load attestation key: %w",
			err,
		)
	}
	defer func() {
		l.Debug("Unloading attestation key")
		ak.Close(provider)
	}()

	attestation, err := provider.AttestPlatform(ak, nonce[:], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tpm2 attestation: %w",
			err,
		)
	}

	return attestation, nil
}

func (c *Client) fetchTPM2Token(
	ctx context.Context,
	td *config.TD,
	totpCode string,
	attestation *attest.PlatformParameters,
	nonce []byte,
) (*vaultapi.Secret, error) {
	l := logger.FromContext(ctx)

	path := "auth/" + td.VaultPath + "/tpm2/" + td.Name + "/login"

	jsonAttestation, err := json.Marshal(attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to json-marshal tpm2 attestation: %w",
			err,
		)
	}

	l.Debug("Requesting tpm2 attested token from vault",
		zap.String("vault_addr", c.vault.Address()),
		zap.String("vault_path", path),
	)

	return c.vault.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"totp":        totpCode,
		"attestation": base64.StdEncoding.EncodeToString(jsonAttestation),
		"nonce":       base64.StdEncoding.EncodeToString(nonce[:]),
	})
}
