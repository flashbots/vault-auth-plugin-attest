package plugin

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/flashbots/vault-auth-plugin-attest/tpm2"
	"github.com/flashbots/vault-auth-plugin-attest/types"
	"github.com/google/go-attestation/attest"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) fetchTPM2(
	ctx context.Context,
	req *logical.Request,
	name string,
) (*tpm2.TPM2, error) {
	l := b.Logger()

	l.Debug("fetching domain from storage",
		"attestation_type", "tpm2",
		"domain", name,
	)

	td, err := b.loadTPM2(ctx, req.Storage, name)
	if err != nil {
		msg := "failed to fetch domain from storage"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", name,
			"error", err,
		)
		return nil, fmt.Errorf("%s: %w", msg, err)
	}
	if td == nil {
		msg := "domain is not configured"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", name,
		)
		return nil, fmt.Errorf("%s: tpm2/%s", msg, name)
	}

	td.Name = name

	return td, nil
}

func (b *backend) pushTPM2(
	ctx context.Context,
	req *logical.Request,
	td *tpm2.TPM2,
) error {
	l := b.Logger()

	l.Debug("pushing domain into storage",
		"attestation_type", "tpm2",
		"domain", td.Name,
	)

	if err := b.saveTPM2(ctx, req.Storage, td); err != nil {
		msg := "failed to push domain into storage"
		b.Logger().Error(msg,
			"attestation_type", "tdx",
			"domain", td.Name,
			"error", err,
		)
		return fmt.Errorf("%s: %w", msg, err)
	}

	return nil
}

func (b *backend) upsertTPM2(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
	name string,
) (*tpm2.TPM2, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	l := b.Logger()

	l.Debug("fetching domain from storage",
		"attestation_type", "tpm2",
		"domain", name,
	)

	td, err := b.loadTPM2(ctx, req.Storage, name)
	if err != nil {
		msg := "failed to fetch domain from storage"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", name,
			"error", err,
		)
		return nil, false, fmt.Errorf("%s: %w", msg, err)
	}

	akPublic, akPublicOk, errs := types.BytesFromFieldData(data, "tpm2_ak_public", nil)

	var (
		pcrs   = [24]*types.Byte32{}
		pcrsOk = [24]bool{}
	)
	for idx := 0; idx < 24; idx++ {
		pcrs[idx], pcrsOk[idx], errs = types.Byte32FromFieldData(data, fmt.Sprintf("tpm2_pcr%02d", idx), errs)
	}

	if err := errs.ErrorOrNil(); err != nil {
		msg := "failed to read parameters for tpm2 entry"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", name,
			"error", err,
		)
		return nil, false, fmt.Errorf("%s: %w", msg, err)
	}

	if td != nil {
		l.Debug("updating domain",
			"attestation_type", "tpm2",
			"domain", name,
		)

		td.Name = name // name is not stored as a field

		if totpSecret, ok := data.GetOk("totp_secret"); ok {
			td.TOTPSecret = totpSecret.(string)
		}

		if akPublicOk {
			td.AKPublic = akPublic
		}
		for idx, pcr := range pcrs {
			if pcrsOk[idx] {
				td.PCRs[idx] = pcr
			}
		}

		return td, false, nil
	}

	l.Debug("creating domain",
		"attestation_type", "tpm2",
		"domain", name,
	)

	if akPublic == nil {
		return nil, false, errors.New("`tpm2_ak_public` field is required")
	}

	td = &tpm2.TPM2{
		Name:       name,
		TOTPSecret: data.Get("totp_secret").(string),
		AKPublic:   akPublic,
		PCRs:       pcrs,
	}

	return td, true, nil
}

func (b *backend) parseTPM2Attestation(
	ctx context.Context,
	data *framework.FieldData,
	td *tpm2.TPM2,
) (*attest.PlatformParameters, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l := b.Logger()

	attestationBase64 := data.Get("attestation").(string)

	if attestationBase64 == "" {
		return nil, errors.New("`attestation` field is required")
	}

	attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
	if err != nil {
		msg := "failed to base64-decode tpm2 attestation report"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", td.Name,
			"error", err,
		)
		return nil, fmt.Errorf("%s: %w", msg, err)
	}

	attestation := &attest.PlatformParameters{}
	if err := json.Unmarshal(attestationBytes, attestation); err != nil {
		msg := "failed to json-unmarshal tpm2 attestation report"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", td.Name,
			"error", err,
		)
		return nil, fmt.Errorf("%s: %w", msg, err)
	}

	if subtle.ConstantTimeCompare(td.AKPublic, attestation.Public) == 0 {
		msg := "unexpected tpm2 attestation key"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", td.Name,
		)
		return nil, errors.New(msg)
	}

	return attestation, nil
}

func (b *backend) validateTPM2Attestation(
	ctx context.Context,
	td *tpm2.TPM2,
	attestation *attest.PlatformParameters,
	nonce string,
	errs *multierror.Error,
) *multierror.Error {
	if err := ctx.Err(); err != nil {
		return multierror.Append(errs, err)
	}

	l := b.Logger()

	l.Debug("validating tpm2 attestation",
		"attestation_type", "tpm2",
		"domain", td.Name,
	)

	akPublic, err := attest.ParseAKPublic(attest.TPMVersion20, td.AKPublic)
	if err != nil {
		msg := "failed to parse public tpm2 attestation key"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", td.Name,
			"error", err,
		)
		return multierror.Append(errs, fmt.Errorf("%s: %w", msg, err))
	}

	_nonce, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		msg := "failed to base64-decode tpm2 nonce"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", td.Name,
			"error", err,
		)
		return multierror.Append(errs, fmt.Errorf("%s: %w", msg, err))
	}

	if err := akPublic.VerifyAll(attestation.Quotes, attestation.PCRs, _nonce); err != nil {
		msg := "failed to verify tpm2 attestation"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", td.Name,
			"error", err,
		)
		errs = multierror.Append(errs, fmt.Errorf("%s: %w", msg, err))
	}

	eventlog, errParseEventLog := attest.ParseEventLog(attestation.EventLog)
	if errParseEventLog != nil {
		msg := "failed to parse tpm2 event log"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", td.Name,
			"error", err,
		)
		errs = multierror.Append(errs, fmt.Errorf("%s: %w", msg, err))
	}

	if _, err := eventlog.Verify(attestation.PCRs); err != nil {
		msg := "failed to verify tpm2 event log"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", td.Name,
			"error", err,
		)
		errs = multierror.Append(errs, fmt.Errorf("%s: %w", msg, err))
	}

	return errs
}

func (b *backend) verifyTPM2Attestation(
	ctx context.Context,
	td *tpm2.TPM2,
	attestation *attest.PlatformParameters,
	errs *multierror.Error,
) *multierror.Error {
	if err := ctx.Err(); err != nil {
		return multierror.Append(errs, err)
	}

	l := b.Logger()

	l.Debug("verifying tpm2 attestation",
		"attestation_type", "tpm2",
		"domain", td.Name,
	)

	reported, ignored := td.MatchesAttestation(attestation)

	errs = multierror.Append(errs, reported...)

	if len(ignored) > 0 {
		l.Debug("finished verifying tpm2 attestation",
			"attestation_type", "tpm2",
			"domain", td.Name,
			"ignored", b.multierror(ignored...),
		)
	}

	return errs
}

func (b *backend) loginTPM2(
	ctx context.Context,
	td *tpm2.TPM2,
	errs *multierror.Error,
) (*logical.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l := b.Logger()

	if err := errs.ErrorOrNil(); err != nil {
		msg := "failed to login trusted domain"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", td.Name,
			"error", err,
		)
		return nil, fmt.Errorf("%s: %w", msg, err)
	}

	auth := &logical.Auth{
		Metadata: map[string]string{"tpm2": td.Name},
		Alias:    &logical.Alias{Name: "tpm2/" + td.Name},
	}
	td.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}
