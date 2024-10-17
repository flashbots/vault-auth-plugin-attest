package plugin

import (
	"context"
	"crypto/tls"

	appconfig "github.com/flashbots/vault-auth-plugin-attest/config"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

func ServeMultiplex(cfg *appconfig.Config) error {
	return plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: backendFactoryFunc(cfg),
		TLSProviderFunc:    tlsProviderFunc(cfg),
	})
}

func backendFactoryFunc(
	cfg *appconfig.Config,
) func(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	return func(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
		b := newBackend(cfg)

		if err := b.Backend.Setup(ctx, c); err != nil {
			return nil, err
		}

		return b, nil
	}
}

func tlsProviderFunc(cfg *appconfig.Config) func() (*tls.Config, error) {
	return vaultapi.VaultPluginTLSProvider(&vaultapi.TLSConfig{
		CACert:        cfg.HTTP.CACert,
		CAPath:        cfg.HTTP.CAPath,
		ClientCert:    cfg.HTTP.ClientCert,
		ClientKey:     cfg.HTTP.ClientKey,
		Insecure:      cfg.HTTP.Insecure,
		TLSServerName: cfg.HTTP.TLSServerName,
	})
}
