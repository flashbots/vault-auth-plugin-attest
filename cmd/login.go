package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/flashbots/vault-auth-plugin-attest/logger"
	"github.com/flashbots/vault-auth-plugin-attest/vault/client"
	"go.uber.org/zap"

	"github.com/urfave/cli/v2"
)

const (
	categoryTD    = "td"
	categoryVault = "vault"
)

func CommandLogin(cfg *config.Config) *cli.Command {
	cfg.TD = &config.TD{}
	cfg.Vault = &config.Vault{}

	flagsGeneral := []cli.Flag{
		&cli.StringFlag{ // --format
			Destination: &cfg.Format,
			EnvVars:     []string{"VAULT_FORMAT"},
			Name:        "format",
			Usage:       "set the cli output format (allowed values: " + strings.Join(config.Formats, ", ") + ")",
			Value:       "table",
		},

		&cli.BoolFlag{ // --verbose
			Destination: &cfg.Verbose,
			Name:        "verbose",
			Usage:       "log the detailed command execution progress",
			Value:       false,
		},
	}

	flagsTD := []cli.Flag{
		&cli.StringFlag{ // --td-attestation-type
			Category:    strings.ToUpper(categoryTD),
			Destination: &cfg.TD.AttestationType,
			Name:        categoryTD + "-attestation-type",
			Usage:       "attestation `type` (allowed values: tdx, tpm2)",
			Value:       "tdx",
		},

		&cli.StringFlag{ // --td-totp-secret
			Category:    strings.ToUpper(categoryTD),
			Destination: &cfg.TD.TOTPSecret,
			Name:        categoryTD + "-totp-secret",
			Usage:       "totp `secret/path` that will be used for authentication",
			Value:       ".totp-secret",
		},

		&cli.StringFlag{ // --td-vault-path
			Category:    strings.ToUpper(categoryTD),
			Destination: &cfg.TD.VaultPath,
			Name:        categoryTD + "-vault-path",
			Usage:       "remote `path` in vault where the attested auth method is mounted",
			Value:       "attest",
		},
	}

	flagsVault := []cli.Flag{
		&cli.StringFlag{ // --vault-address
			Category:    strings.ToUpper(categoryVault),
			Destination: &cfg.Vault.Address,
			EnvVars:     []string{"VAULT_ADDR"},
			Name:        "address",
			Usage:       "`address` of the vault server",
			Value:       "https://127.0.0.1:8200",
		},

		&cli.BoolFlag{ // --vault-no-print
			Category:    strings.ToUpper(categoryVault),
			Destination: &cfg.Vault.NoPrint,
			Name:        "no-print",
			Usage:       "do not display the token (it will be still be stored to the configured token helper)",
			Value:       false,
		},

		&cli.BoolFlag{ // --vault-no-store
			Category:    strings.ToUpper(categoryVault),
			Destination: &cfg.Vault.NoStore,
			Name:        "no-store",
			Usage:       "do not persist the token to the token helper (it will only be displayed in the command output)",
			Value:       false,
		},

		&cli.DurationFlag{ // --vault-timeout
			Category:    strings.ToUpper(categoryVault),
			Destination: &cfg.Vault.Timeout,
			Name:        "timeout",
			Usage:       "`timeout` for the operations with vault",
			Value:       5 * time.Second,
		},
	}

	return &cli.Command{
		Name:  "login",
		Usage: "login to vault via attested auth plugin",

		ArgsUsage: " [td-name]",

		Flags: slices.Concat(
			flagsGeneral,
			flagsTD,
			flagsVault,
		),

		Before: func(clictx *cli.Context) error {
			if clictx.Args().Len() != 1 {
				return errors.New("must provide exactly 1 trusted domain name as an argument")
			}
			cfg.TD.Name = clictx.Args().First()

			return cfg.Preprocess()
		},

		Action: func(_ *cli.Context) error {
			// setup

			ctx := context.Background()
			if cfg.Verbose {
				l, err := logger.New()
				if err != nil {
					return err
				}
				zap.ReplaceGlobals(l)
				ctx = logger.ContextWith(ctx, l)
			}

			cli, err := client.New(cfg)
			if err != nil {
				return nil
			}

			// run

			return cli.Login(ctx, cfg.TD)
		},
	}
}
