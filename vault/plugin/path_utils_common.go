package plugin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/globals"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/pquerna/otp/totp"
)

func (b *backend) getName(
	ctx context.Context,
	data *framework.FieldData,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	name := data.Get("name").(string)
	if name == "" {
		return "", errors.New("`name` field is required")
	}

	return name, nil
}

func (b *backend) getNonce(
	ctx context.Context,
	data *framework.FieldData,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	name := data.Get("nonce").(string)
	if name == "" {
		return "", errors.New("`nonce` field is required")
	}

	return name, nil
}

func (b *backend) encodeTD(
	ctx context.Context,
	td TD,
) (map[string]interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l := b.Logger()

	res := make(map[string]interface{})
	if err := mapstructure.Decode(td, &res); err != nil {
		msg := "failed to encode td entry"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", td.GetName(),
			"error", err,
		)
		return nil, fmt.Errorf("%s: %w", msg, err)
	}

	td.PopulateTokenData(res)

	return res, nil
}

func (b *backend) generateTOTPSecret(
	ctx context.Context,
	td TD,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l := b.Logger()

	l.Debug("generating totp secret",
		"attestation_type", td.AttestationType(),
		"domain", td.GetName(),
	)

	totpKey, err := totp.Generate(totp.GenerateOpts{
		AccountName: td.GetName(),
		Algorithm:   globals.TOTPAlgorithm,
		Digits:      globals.TOTPDigits,
		Issuer:      "vault",
		Period:      uint(globals.TOTPPeriod / time.Second),
		Rand:        b.Rand(),
	})
	if err != nil {
		msg := "failed to generate totp secret"
		l.Error(msg,
			"attestation_type", td.AttestationType(),
			"domain", td.GetName(),
			"error", err,
		)
		return fmt.Errorf("%s: %w", msg, err)
	}

	td.SetTOTPSecret(totpKey.Secret())

	return nil
}

func (b *backend) validateTOTP(
	ctx context.Context,
	data *framework.FieldData,
	td TD,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l := b.Logger()

	l.Debug("validating totp code",
		"attestation_type", td.AttestationType(),
		"domain", td.GetName(),
	)

	totpCode := data.Get("totp").(string)
	if totpCode == "" {
		msg := "`totp` field is required"
		return errors.New(msg)
	}

	valid, err := totp.ValidateCustom(
		totpCode,
		td.GetTOTPSecret(),
		time.Now().UTC(),
		b.totpOptions,
	)
	if err != nil {
		msg := "failed to validate totp code"
		l.Error(msg,
			"attestation_type", td.AttestationType(),
			"domain", td.GetName(),
			"error", err,
		)
		return fmt.Errorf("%s: %w", msg, err)
	}
	if !valid {
		msg := "totp code is invalid"
		l.Error(msg,
			"attestation_type", td.AttestationType(),
			"domain", td.GetName(),
		)
		return errors.New(msg)
	}

	entry := td.AttestationType() + "/" + td.GetName() + "/totp/" + totpCode

	if _, used := b.totpUsedCodes.Get(entry); used {
		msg := "totp code was already used"
		l.Error(msg,
			"attestation_type", td.AttestationType(),
			"domain", td.GetName(),
		)
		return errors.New(msg)
	}
	if err := b.totpUsedCodes.Add(entry, nil, 3*globals.TOTPPeriod); err != nil {
		msg := "failed to validate totp code"
		l.Error(msg,
			"attestation_type", td.AttestationType(),
			"domain", td.GetName(),
			"error", err,
		)
		return fmt.Errorf("%s: %w", msg, err)
	}

	return nil
}

func (b *backend) generateNonce(
	ctx context.Context,
	td TD,
	size int,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	l := b.Logger()

	l.Debug("generating nonce",
		"attestation_type", td.AttestationType(),
		"domain", td.GetName(),
	)

	for iter := 0; iter < 5; iter++ {
		_nonce := make([]byte, size)
		if _, err := io.ReadFull(b.Rand(), _nonce); err != nil {
			msg := "failed to generate nonce"
			l.Error(msg,
				"attestation_type", td.AttestationType(),
				"domain", td.GetName(),
				"error", err,
			)
			return "", fmt.Errorf("%s: %w", msg, err)
		}
		nonce := base64.StdEncoding.EncodeToString(_nonce)

		entry := td.AttestationType() + "/" + td.GetName() + "/nonce/" + nonce

		if _, used := b.totpUsedCodes.Get(entry); used {
			l.Warn("regenerating nonce due to a collision",
				"attestation_type", td.AttestationType(),
				"domain", td.GetName(),
			)
			continue
		}

		if err := b.totpUsedCodes.Add(entry, nil, globals.NoncePeriod); err != nil {
			msg := "failed to generate nonce"
			l.Error(msg,
				"attestation_type", td.AttestationType(),
				"domain", td.GetName(),
				"error", err,
			)
			return "", fmt.Errorf("%s: %w", msg, err)
		}

		return nonce, nil
	}

	msg := "failed to generate nonce after 5 iterations"
	l.Error(msg,
		"attestation_type", td.AttestationType(),
		"domain", td.GetName(),
	)
	return "", errors.New(msg)
}

func (b *backend) validateNonce(
	ctx context.Context,
	td TD,
	nonce string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l := b.Logger()

	l.Debug("validating nonce",
		"attestation_type", td.AttestationType(),
		"domain", td.GetName(),
	)

	entry := td.AttestationType() + "/" + td.GetName() + "/nonce/" + nonce
	if _, present := b.totpUsedCodes.Get(entry); !present {
		msg := "unexpected nonce"
		l.Error(msg,
			"attestation_type", td.AttestationType(),
			"domain", td.GetName(),
		)
		return errors.New(msg)
	}

	return nil
}

func (b *backend) parseTokenFields(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
	td TD,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l := b.Logger()

	if err := td.ParseTokenFields(req, data); err != nil {
		msg := "failed to parse token parameters"
		l.Error(msg,
			"attestation_type", td.AttestationType(),
			"domain", td.GetName(),
			"error", err,
		)
		return fmt.Errorf("%s: %w", msg, err)
	}

	return nil
}
