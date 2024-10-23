package plugin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/flashbots/vault-auth-plugin-attest/tdx"
	"github.com/flashbots/vault-auth-plugin-attest/types"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	tdxabi "github.com/google/go-tdx-guest/abi"
	txdcheck "github.com/google/go-tdx-guest/proto/checkconfig"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
)

func (b *backend) fetchTDX(
	ctx context.Context,
	req *logical.Request,
	name string,
) (*tdx.TDX, error) {
	l := b.Logger()

	l.Debug("fetching domain from storage",
		"attestation_type", "tdx",
		"domain", name,
	)

	td, err := b.loadTDX(ctx, req.Storage, name)
	if err != nil {
		msg := "failed to fetch domain from storage"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", name,
			"error", err,
		)
		return nil, fmt.Errorf("%s: %w", msg, err)
	}
	if td == nil {
		msg := "domain is not configured"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", name,
		)
		return nil, fmt.Errorf("%s: tdx/%s", msg, name)
	}

	td.Name = name

	return td, nil
}

func (b *backend) pushTDX(
	ctx context.Context,
	req *logical.Request,
	td *tdx.TDX,
) error {
	l := b.Logger()

	l.Debug("pushing domain into storage",
		"attestation_type", "tdx",
		"domain", td.Name,
	)

	if err := b.saveTDX(ctx, req.Storage, td); err != nil {
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

func (b *backend) upsertTDX(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
	name string,
) (*tdx.TDX, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	l := b.Logger()

	l.Debug("fetching domain from storage",
		"attestation_type", "tdx",
		"domain", name,
	)

	td, err := b.loadTDX(ctx, req.Storage, name)
	if err != nil {
		msg := "failed to fetch domain from storage"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", name,
			"error", err,
		)
		return nil, false, fmt.Errorf("%s: %w", msg, err)
	}

	mrOwner, mrOwnerOk, errs := types.Byte48FromFieldData(data, "tdx_mr_owner", nil)
	mrOwnerConfig, mrOwnerConfigOk, errs := types.Byte48FromFieldData(data, "tdx_mr_owner_config", errs)
	mrConfigID, mrConfigIDOk, errs := types.Byte48FromFieldData(data, "tdx_mr_config_id", errs)
	mrTD, mrTDOk, errs := types.Byte48FromFieldData(data, "tdx_mr_td", errs)
	rtmr0, rtmr0Ok, errs := types.Byte48FromFieldData(data, "tdx_rtmr0", errs)
	rtmr1, rtmr1Ok, errs := types.Byte48FromFieldData(data, "tdx_rtmr1", errs)
	rtmr2, rtmr2Ok, errs := types.Byte48FromFieldData(data, "tdx_rtmr2", errs)
	rtmr3, rtmr3Ok, errs := types.Byte48FromFieldData(data, "tdx_rtmr3", errs)

	if err := errs.ErrorOrNil(); err != nil {
		msg := "failed to read parameters for tdx entry"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", name,
			"error", err,
		)
		return nil, false, fmt.Errorf("%s: %w", msg, err)
	}

	if td != nil {
		l.Debug("updating domain",
			"attestation_type", "tdx",
			"domain", name,
		)

		td.Name = name // name is not stored as a field

		if totpSecret, ok := data.GetOk("totp_secret"); ok {
			td.TOTPSecret = totpSecret.(string)
		}
		if checkDebug, ok := data.GetOk("tdx_check_debug"); ok {
			td.CheckDebug = checkDebug.(bool)
		}
		if checkSeptVeDisable, ok := data.GetOk("tdx_check_sept_ve_disable"); ok {
			td.CheckSeptVeDisable = checkSeptVeDisable.(bool)
		}

		if mrOwnerOk {
			td.MrOwner = mrOwner
		}
		if mrOwnerConfigOk {
			td.MrOwnerConfig = mrOwnerConfig
		}
		if mrConfigIDOk {
			td.MrConfigID = mrConfigID
		}
		if mrTDOk {
			td.MrTD = mrTD
		}
		if rtmr0Ok {
			td.RTMR0 = rtmr0
		}
		if rtmr1Ok {
			td.RTMR1 = rtmr1
		}
		if rtmr2Ok {
			td.RTMR2 = rtmr2
		}
		if rtmr3Ok {
			td.RTMR3 = rtmr3
		}

		return td, false, nil
	}

	l.Debug("creating domain",
		"attestation_type", "tdx",
		"domain", name,
	)

	td = &tdx.TDX{
		Name:               name,
		TOTPSecret:         data.Get("totp_secret").(string),
		MrOwner:            mrOwner,
		MrOwnerConfig:      mrOwnerConfig,
		MrConfigID:         mrConfigID,
		MrTD:               mrTD,
		RTMR0:              rtmr0,
		RTMR1:              rtmr1,
		RTMR2:              rtmr2,
		RTMR3:              rtmr3,
		CheckDebug:         data.Get("tdx_check_debug").(bool),
		CheckSeptVeDisable: data.Get("tdx_check_sept_ve_disable").(bool),
	}

	return td, true, nil
}

func (b *backend) parseTDXQuote(
	ctx context.Context,
	data *framework.FieldData,
	td *tdx.TDX,
) (*tdxpb.QuoteV4, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l := b.Logger()

	l.Debug("parsing tdx quote",
		"attestation_type", "tdx",
		"domain", td.Name,
	)

	quoteBase64 := data.Get("quote").(string)
	if quoteBase64 == "" {
		return nil, errors.New("`quote` field is required")
	}

	quoteBytes, err := base64.StdEncoding.DecodeString(quoteBase64)
	if err != nil {
		msg := "failed to base64-decode tdx quote"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", td.Name,
			"error", err,
		)
		return nil, fmt.Errorf("%s: %w", msg, err)
	}

	quote, err := tdxabi.QuoteToProto(quoteBytes)
	if err != nil {
		msg := "failed to abi-parse tdx quote"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", td.Name,
			"error", err,
		)
		return nil, fmt.Errorf("%s: %w", msg, err)
	}

	quoteV4 := quote.(*tdxpb.QuoteV4)
	if quoteV4 == nil {
		msg := "unknown tdx quote format"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", td.Name,
		)
		return nil, errors.New(msg)
	}

	return quoteV4, nil
}

func (b *backend) validateTDXQuote(
	ctx context.Context,
	td *tdx.TDX,
	quote *tdxpb.QuoteV4,
	errs *multierror.Error,
) *multierror.Error {
	if err := ctx.Err(); err != nil {
		return multierror.Append(errs, err)
	}

	l := b.Logger()

	l.Debug("validating tdx quote",
		"attestation_type", "tdx",
		"domain", td.Name,
	)

	sopts, err := tdxverify.RootOfTrustToOptions(
		&txdcheck.RootOfTrust{}, // TODO: make configurable
	)
	if err != nil {
		msg := "failed to validate tdx quote"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", td.Name,
			"error", err,
		)
		return multierror.Append(errs, fmt.Errorf("%s: %w", msg, err))
	}

	sopts.Getter = &tdxtrust.RetryHTTPSGetter{
		Getter: &tdxtrust.SimpleHTTPSGetter{},
	}
	if err := tdxverify.TdxQuote(quote, sopts); err != nil {
		msg := "failed to validate tdx quote"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", td.Name,
			"error", err,
		)
		return multierror.Append(errs, fmt.Errorf("%s: %w", msg, err))
	}

	return errs
}

func (b *backend) verifyTDXQuote(
	ctx context.Context,
	td *tdx.TDX,
	quote *tdxpb.QuoteV4,
	errs *multierror.Error,
) *multierror.Error {
	if err := ctx.Err(); err != nil {
		return multierror.Append(errs, err)
	}

	l := b.Logger()

	l.Debug("verifying tdx quote",
		"attestation_type", "tdx",
		"domain", td.Name,
	)

	reported, ignored := td.MatchesQuoteV4(quote)

	errs = multierror.Append(errs, reported...)

	if len(ignored) > 0 {
		l.Debug("finished verifying tdx quote",
			"attestation_type", "tdx",
			"domain", td.Name,
			"ignored", b.multierror(ignored...),
		)
	}

	return errs
}

func (b *backend) loginTDX(
	ctx context.Context,
	td *tdx.TDX,
	errs *multierror.Error,
) (*logical.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l := b.Logger()

	if err := errs.ErrorOrNil(); err != nil {
		msg := "failed to login trusted domain"
		l.Error(msg,
			"attestation_type", "tdx",
			"domain", td.Name,
			"error", err,
		)
		return nil, fmt.Errorf("%s: %w", msg, err)
	}

	auth := &logical.Auth{
		Metadata: map[string]string{"tdx": td.Name},
		Alias:    &logical.Alias{Name: "tdx/" + td.Name},
	}
	td.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}
