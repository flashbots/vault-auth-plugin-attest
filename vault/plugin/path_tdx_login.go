package plugin

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const helpTDXLoginSynopsys = `
Log in with TOTP code and TDX attestation quote.
`

const helpTDXLoginDescription = `
This endpoint authenticates using TOTP code and TDX attestation quote.
`

func pathTDXLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "tdx/" + framework.GenericNameRegex("name") + "/login",
		HelpSynopsis:    helpTDXLoginSynopsys,
		HelpDescription: helpTDXLoginDescription,

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "TDX trusted domain name",
			},

			"totp": {
				Type:        framework.TypeString,
				Description: "TOTP code",
			},

			"quote": {
				Type:        framework.TypeString,
				Description: "TDX attestation quote",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTDXLogin,
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.pathTDXAliasLookahead,
			},
		},
	}
}

func (b *backend) pathTDXAliasLookahead(
	ctx context.Context,
	_ *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, err := b.getName(ctx, data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{Name: "tdx/" + name},
		},
	}, nil
}

func (b *backend) pathTDXLogin(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	return b.sanitise(func() (*logical.Response, error) {
		name, err := b.getName(ctx, data)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		td, err := b.fetchTDX(ctx, req, name)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		err = b.validateTOTP(ctx, data, td)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		quote, err := b.parseTDXQuote(ctx, data, td)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		nonce := base64.StdEncoding.EncodeToString(quote.TdQuoteBody.ReportData)
		err = b.validateNonce(ctx, td, nonce)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		errs := b.validateTDXQuote(ctx, td, quote, b.multierror())
		errs = b.verifyTDXQuote(ctx, td, quote, errs)

		auth, err := b.loginTDX(ctx, td, errs)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		return auth, nil
	})
}
