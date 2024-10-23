package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const helpTPM2Synopsys = `
Manage TPM 2.0 trusted domains that are allowed to authenticate.
`

const helpTPM2Description = `
This endpoint allows you to create, read, update, and delete TPM 2.0
trusted domains that are allowed to authenticate.
`

const (
	opPrefixTPM2 = "tpm2-op-prefix"
)

func pathTPM2(b *backend) *framework.Path {
	path := &framework.Path{
		Pattern:         "tpm2/" + framework.GenericNameRegex("name"),
		HelpSynopsis:    helpTPM2Synopsys,
		HelpDescription: helpTPM2Description,

		ExistenceCheck: b.pathTPM2Exists,

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "TPM 2.0 trusted domain name",
			},

			// TOTP

			"totp_secret": {
				Type:        framework.TypeString,
				Description: "Secret used to generate TOTP codes",

				DisplayAttrs: &framework.DisplayAttributes{
					Name:        "TOTP secret",
					Description: "Secret used to generate TOTP codes (can only be set, and is never shown in the UI)",
					Sensitive:   true,
				},
			},

			// AK

			"tpm2_ak_public": {
				Type:        framework.TypeString,
				Description: "Public part of the attestation key used to generate TPM 2.0 attestations/quotes",

				DisplayAttrs: &framework.DisplayAttributes{
					Name:        "AK",
					Description: "Public part of the attestation key used to generate TPM 2.0 attestations/quotes (base64-encoded)",
					EditType:    "textarea",
				},
			},

			// PCRs are filled down below
		},

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: opPrefixTPM2,
			OperationSuffix: "tpm2",
			Action:          "Create",
			ItemType:        "TPM2",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathTPM2Upsert,
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTPM2Upsert,
			},

			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathTPM2Read,
			},

			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathTPM2Delete,
			},
		},
	}

	for idx := 0; idx < 24; idx++ {
		path.Fields[fmt.Sprintf("tpm2_pcr%02d", idx)] = &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: fmt.Sprintf("Expected measurement of platform configuration register #%d", idx),

			DisplayAttrs: &framework.DisplayAttributes{
				Name:        fmt.Sprintf("PCR[%d]", idx),
				Description: fmt.Sprintf("Expected measurement of platform configuration register #%d", idx),
			},
		}
	}

	tokenutil.AddTokenFields(path.Fields)

	return path
}

func pathTPM2List(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "tpm2/?",
		HelpSynopsis:    helpTPM2Synopsys,
		HelpDescription: helpTPM2Description,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathTPM2List,
			},
		},

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: opPrefixTPM2,
			OperationSuffix: "tpm2",
			ItemType:        "TPM2",
			Navigation:      true,
		},
	}
}

func (b *backend) pathTPM2Exists(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (bool, error) {
	td, err := b.loadTPM2(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return td != nil, nil
}

func (b *backend) pathTPM2Upsert(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, err := b.getName(ctx, data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	td, isNew, err := b.upsertTPM2(ctx, req, data, name)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	if err := b.parseTokenFields(ctx, req, data, td); err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	if td.TOTPSecret == "" {
		if err := b.generateTOTPSecret(ctx, td); err != nil {
			return logical.ErrorResponse(err.Error()), err
		}
	}

	if err := b.pushTPM2(ctx, req, td); err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	_data, err := b.encodeTD(ctx, td)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}
	for idx, pcr := range td.PCRs {
		if pcr != nil {
			_data[fmt.Sprintf("tpm2_pcr%02d", idx)] = pcr.String()
		}
	}
	if isNew { // show totp secret only when creating
		_data["totp_secret"] = td.TOTPSecret
	}
	return &logical.Response{
		Data: _data,
	}, nil
}

func (b *backend) pathTPM2Read(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, err := b.getName(ctx, data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	td, err := b.fetchTPM2(ctx, req, name)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	_data, err := b.encodeTD(ctx, td)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}
	for idx, pcr := range td.PCRs {
		if pcr != nil {
			_data[fmt.Sprintf("tpm2_pcr%02d", idx)] = pcr.String()
		}
	}

	return &logical.Response{
		Data: _data,
	}, nil
}

func (b *backend) pathTPM2Delete(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	l := b.Logger()

	name := data.Get("name").(string)

	l.Debug("deleting domain",
		"attestation_type", "tpm2",
		"domain", name,
	)

	if err := b.deleteTPM2(ctx, req.Storage, name); err != nil {
		msg := "failed to delete domain"
		l.Error(msg,
			"attestation_type", "tpm2",
			"domain", name,
			"error", err,
		)
		return logical.ErrorResponse("%s: %s", msg, err), fmt.Errorf("%s: %w", msg, err)
	}

	return nil, nil
}

func (b *backend) pathTPM2List(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	l := b.Logger()

	tds, err := b.listTPM2(ctx, req.Storage)

	if err != nil {
		msg := "failed to list domains"
		l.Error(msg,
			"attestation_type", "tpm2",
			"error", err,
		)
		return logical.ErrorResponse("%s: %s", msg, err), fmt.Errorf("%s: %w", msg, err)
	}

	return logical.ListResponse(tds), nil
}
