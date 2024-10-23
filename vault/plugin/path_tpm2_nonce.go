package plugin

import (
	"context"

	"github.com/flashbots/vault-auth-plugin-attest/globals"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const helpTPM2NonceSynopsys = `
Generate TPM 2.0 attestation nonce.
`

const helpTPM2NonceDescription = `
Request vault to generate a TPM 2.0 attestation nonce that client will need to
include into the attestation report in order to complete the authentication
sequence.
`

func pathTPM2Nonce(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "tpm2/" + framework.GenericNameRegex("name") + "/nonce",
		HelpSynopsis:    helpTPM2NonceSynopsys,
		HelpDescription: helpTPM2NonceDescription,

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "TPM 2.0 trusted domain name",
			},

			"totp": {
				Type:        framework.TypeString,
				Description: "TOTP code",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathTPM2NonceGenerate,
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTPM2NonceGenerate,
			},
		},

		ExistenceCheck: func(ctx context.Context, r *logical.Request, fd *framework.FieldData) (bool, error) {
			return false, nil
		},
	}
}

func (b *backend) pathTPM2NonceGenerate(
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

		nonce, err := b.generateNonce(ctx, td, globals.TPM2NonceSize)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"ak_public": td.AKPublic.String(),
				"nonce":     nonce,
			},
		}, nil
	})
}
