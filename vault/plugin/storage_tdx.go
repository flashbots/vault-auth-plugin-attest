package plugin

import (
	"context"

	"github.com/flashbots/vault-auth-plugin-attest/tdx"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) loadTDX(
	ctx context.Context,
	storage logical.Storage,
	name string,
) (*tdx.TDX, error) {
	entry, err := storage.Get(ctx, "tdx/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	tdx := &tdx.TDX{}
	if err := entry.DecodeJSON(tdx); err != nil {
		return nil, err
	}

	return tdx, nil
}

func (b *backend) saveTDX(
	ctx context.Context,
	storage logical.Storage,
	tdx *tdx.TDX,
) error {
	entry, err := logical.StorageEntryJSON("tdx/"+tdx.Name, tdx)
	if err != nil {
		return err
	}

	return storage.Put(ctx, entry)
}

func (b *backend) deleteTDX(
	ctx context.Context,
	storage logical.Storage,
	name string,
) error {
	return storage.Delete(ctx, "tdx/"+name)
}

func (b *backend) listTDX(
	ctx context.Context,
	storage logical.Storage,
) ([]string, error) {
	return storage.List(ctx, "tdx/")
}
