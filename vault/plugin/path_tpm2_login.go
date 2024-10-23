package plugin

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const helpTPM2LoginSynopsys = `
Log in with TOTP code and TPM 2.0 attestation report.
`

const helpTPM2LoginDescription = `
This endpoint authenticates using TOTP code and TPM 2.0 attestation
report.
`

func pathTPM2Login(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "tpm2/" + framework.GenericNameRegex("name") + "/login",
		HelpSynopsis:    helpTPM2LoginSynopsys,
		HelpDescription: helpTPM2LoginDescription,

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "TPM 2.0 trusted domain name",
			},

			"totp": {
				Type:        framework.TypeString,
				Description: "TOTP code",
			},

			"attestation": {
				Type:        framework.TypeString,
				Description: "TPM 2.0 attestation report",
			},

			"nonce": {
				Type:        framework.TypeString,
				Description: "Nonce used when generating TPM 2.0 attestation report",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTPM2Login,
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.pathTPM2AliasLookahead,
			},
		},
	}
}

func (b *backend) pathTPM2AliasLookahead(
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
			Alias: &logical.Alias{Name: "tpm2/" + name},
		},
	}, nil
}

func (b *backend) pathTPM2Login(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	return b.sanitise(func() (*logical.Response, error) {
		name, err := b.getName(ctx, data)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		td, err := b.fetchTPM2(ctx, req, name)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		err = b.validateTOTP(ctx, data, td)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		attestation, err := b.parseTPM2Attestation(ctx, data, td)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		nonce, err := b.getNonce(ctx, data)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		err = b.validateNonce(ctx, td, nonce)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		errs := b.validateTPM2Attestation(ctx, td, attestation, nonce, b.multierror())
		errs = b.verifyTPM2Attestation(ctx, td, attestation, errs)

		auth, err := b.loginTPM2(ctx, td, errs)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		return auth, nil
	})
}
