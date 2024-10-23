package plugin

import (
	"context"

	"github.com/flashbots/vault-auth-plugin-attest/tpm2"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) loadTPM2(
	ctx context.Context,
	storage logical.Storage,
	name string,
) (*tpm2.TPM2, error) {
	entry, err := storage.Get(ctx, "tpm2/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	tpm2 := &tpm2.TPM2{}
	if err := entry.DecodeJSON(tpm2); err != nil {
		return nil, err
	}

	return tpm2, nil
}

func (b *backend) saveTPM2(
	ctx context.Context,
	storage logical.Storage,
	tpm2 *tpm2.TPM2,
) error {
	entry, err := logical.StorageEntryJSON("tpm2/"+tpm2.Name, tpm2)
	if err != nil {
		return err
	}

	return storage.Put(ctx, entry)
}

func (b *backend) deleteTPM2(
	ctx context.Context,
	storage logical.Storage,
	name string,
) error {
	return storage.Delete(ctx, "tpm2/"+name)
}

func (b *backend) listTPM2(
	ctx context.Context,
	storage logical.Storage,
) ([]string, error) {
	return storage.List(ctx, "tpm2/")
}
