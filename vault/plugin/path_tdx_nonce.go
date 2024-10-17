package plugin

import (
	"context"
	"encoding/base64"
	"io"
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/globals"
	"github.com/flashbots/vault-auth-plugin-attest/types"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/pquerna/otp/totp"
)

const helpTDXNonceSynopsys = `
Generate TDX attestation nonce.
`

const helpTDXNonceDescription = `
Request vault to generate a TDX attestations nonce that client will need to
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
				Description: "TDX domain name",
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
	var (
		name, nonce string
		tdx         *types.TDX
		err         error
	)

	l := b.Logger()

	{ // fetch the storage
		name = data.Get("name").(string)
		if name == "" {
			return b.invalidRequest("tdx domain name is required")
		}

		tdx, err = b.loadTDX(ctx, req.Storage, name)
		if err != nil {
			return b.loggedError("failed to load tdx domain from storage",
				"domain", name,
				"error", err,
			)
		}
		if tdx == nil {
			return b.invalidRequest("tdx domain is not configured: %s",
				name,
			)
		}
	}

	{ // validate totp code
		l.Debug("validating totp code for tdx nonce", "domain", name)

		totpCode := data.Get("totp").(string)
		if totpCode == "" {
			return b.invalidRequest("totp code is required")
		}

		valid, err := totp.ValidateCustom(totpCode, tdx.TOTPSecret, time.Now().UTC(), b.totpOptions)
		if err != nil {
			return b.loggedError("failed to validate totp code",
				"domain", name,
				"error", err,
			)
		}
		if !valid {
			return b.loggedError("totp code is invalid",
				"domain", name,
			)
		}

		entry := name + "/totp/" + totpCode

		if _, used := b.totpUsedCodes.Get(entry); used {
			return b.loggedError("totp code was already used",
				"domain", name,
			)
		}
		if err := b.totpUsedCodes.Add(entry, nil, 3*globals.TOTPPeriod); err != nil {
			return b.loggedError("failed to validate totp code",
				"domain", name,
				"error", err,
			)
		}
	}

	{ // generate nonce
		l.Debug("generating nonce for tdx domain", "domain", name)

		for {
			_nonce := make([]byte, 64)
			if _, err := io.ReadFull(b.Rand(), _nonce); err != nil {
				return b.loggedError("failed to generate tdx nonce",
					"domain", name,
					"error", err,
				)
			}
			nonce = base64.StdEncoding.EncodeToString(_nonce)

			entry := name + "/nonce/" + nonce

			if _, used := b.totpUsedCodes.Get(entry); used {
				l.Warn("regenerating nonce due to a collision", "domain", name)
				continue
			}
			if err := b.totpUsedCodes.Add(entry, nil, globals.NoncePeriod); err != nil {
				return b.loggedError("failed to generate the nonce",
					"domain", name,
					"error", err,
				)
			}

			break
		}
	}

	{ // return result
		return &logical.Response{
			Data: map[string]interface{}{
				"nonce": nonce,
			},
		}, nil
	}
}
