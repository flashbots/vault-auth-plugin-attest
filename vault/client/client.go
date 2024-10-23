package client

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/flashbots/vault-auth-plugin-attest/globals"
	"github.com/hashicorp/go-multierror"
	"github.com/mattn/go-colorable"
	"github.com/pquerna/otp/totp"

	vaultcli "github.com/hashicorp/cli"
	vaultapi "github.com/hashicorp/vault/api"
	vaultcmd "github.com/hashicorp/vault/command"

	"github.com/hashicorp/vault/api/cliconfig"
	"github.com/hashicorp/vault/api/tokenhelper"
)

type Client struct {
	cfg *config.Vault

	format      string
	formatter   vaultcmd.Formatter
	tokenHelper tokenhelper.TokenHelper
	ui          vaultcli.Ui
	vault       *vaultapi.Client

	totpOptions totp.ValidateOpts
}

const uiAuthTokenNotPersisted = `
Authentication was successful, but the token was not persisted. The
resulting token is shown below for your records.
`

const uiSuccess = `
Success! You are now authenticated. The token information displayed
below is already stored in the token helper. You do NOT need to login
again. Future Vault requests will automatically use this token.
`

func New(cfg *config.Config) (*Client, error) {
	c := vaultapi.DefaultConfig()

	if cfg.Vault.Address != "" {
		c.Address = cfg.Vault.Address
	}
	c.Timeout = cfg.Vault.Timeout
	c.MaxRetries = 0

	if cfg.HTTP.TLSEnabled() {
		err := c.ConfigureTLS(&vaultapi.TLSConfig{
			CACert:        cfg.HTTP.CACert,
			CAPath:        cfg.HTTP.CAPath,
			ClientCert:    cfg.HTTP.ClientCert,
			ClientKey:     cfg.HTTP.ClientKey,
			TLSServerName: cfg.HTTP.TLSServerName,
			Insecure:      cfg.HTTP.Insecure,
		})
		if err != nil {
			return nil, err
		}
	}

	cli, err := vaultapi.NewClient(c)
	if err != nil {
		return nil, err
	}

	tokenHelper, err := cliconfig.DefaultTokenHelper()
	if err != nil {
		return nil, err
	}

	ui := &vaultcmd.VaultUI{
		Ui: &vaultcli.BasicUi{
			Writer: colorable.NewNonColorable(os.Stdout),
		},
	}

	return &Client{
		cfg: cfg.Vault,

		format:      cfg.Format,
		formatter:   vaultcmd.Formatters[cfg.Format],
		tokenHelper: tokenHelper,
		ui:          ui,
		vault:       cli,

		totpOptions: totp.ValidateOpts{
			Algorithm: globals.TOTPAlgorithm,
			Digits:    globals.TOTPDigits,
			Period:    uint(globals.TOTPPeriod / time.Second),
			Skew:      1,
		},
	}, nil
}

func (c *Client) Login(ctx context.Context, td *config.TD) error {
	var (
		secret *vaultapi.Secret
		err    error
	)

	switch td.AttestationType {
	default:
		return fmt.Errorf("unknown attestation type: %s", td.AttestationType)
	case "tdx":
		secret, err = c.loginTDX(ctx, td)
	case "tpm2":
		secret, err = c.loginTPM2(ctx, td)
	}
	if err != nil {
		return err
	}

	token := secret.Auth.ClientToken

	if !c.cfg.NoStore {
		if err := c.tokenHelper.Store(token); err != nil {
			c.ui.Error(uiAuthTokenNotPersisted)
			_ = vaultcmd.OutputSecret(c.ui, secret)
			if err2 := c.outputSecret(secret); err2 != nil {
				return multierror.Append(err, err2)
			}
			return err
		}
	}

	if c.cfg.NoPrint {
		return nil
	}

	c.ui.Output(uiSuccess)

	return c.outputSecret(secret)
}

func (c *Client) outputSecret(secret *vaultapi.Secret) error {
	return c.formatter.Output(c.ui, secret, secret)
}
