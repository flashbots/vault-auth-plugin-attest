package plugin

import (
	"context"

	"github.com/flashbots/vault-auth-plugin-attest/globals"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const helpTDXNonceSynopsys = `
Generate TDX attestation nonce.
`

const helpTDXNonceDescription = `
Request vault to generate a TDX attestation nonce that client will need to
include into the attestation quote in order to complete the authentication
sequence.
`

func pathTDXNonce(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "tdx/" + framework.GenericNameRegex("name") + "/nonce",
		HelpSynopsis:    helpTDXNonceSynopsys,
		HelpDescription: helpTDXNonceDescription,

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "TDX trusted domain name",
			},

			"totp": {
				Type:        framework.TypeString,
				Description: "TOTP code",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathTDXNonceGenerate,
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTDXNonceGenerate,
			},
		},

		ExistenceCheck: func(ctx context.Context, r *logical.Request, fd *framework.FieldData) (bool, error) {
			return false, nil
		},
	}
}

func (b *backend) pathTDXNonceGenerate(
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

		nonce, err := b.generateNonce(ctx, td, globals.TDXNonceSize)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"nonce": nonce,
			},
		}, nil
	})
}
