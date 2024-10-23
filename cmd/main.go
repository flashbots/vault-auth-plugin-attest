package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"

	"github.com/flashbots/vault-auth-plugin-attest/config"
)

var (
	version = "v0.0.0"
)

const (
	categoryHTTP   = "http"
	categoryPlugin = "plugin"

	envPrefix = "VAULT_ATTESTED_AUTH_"
)

func main() {
	cfg := &config.Config{
		HTTP:    &config.HTTP{},
		TD:      &config.TD{},
		Vault:   &config.Vault{},
		Version: version,
	}

	flagsHTTP := []cli.Flag{
		// -ca-cert
		&cli.StringFlag{
			Category:    strings.ToUpper(categoryHTTP),
			Destination: &cfg.HTTP.CACert,
			EnvVars:     []string{envPrefix + "CA_CERT"},
			Name:        "ca-cert",
			Usage:       "`path` to a single PEM-encoded CA certificate to verify the vault's TLS certificate",
		},

		// -ca-path
		&cli.StringFlag{
			Category:    strings.ToUpper(categoryHTTP),
			Destination: &cfg.HTTP.CAPath,
			EnvVars:     []string{envPrefix + "CA_PATH"},
			Name:        "ca-path",
			Usage:       "`path` to a directory of PEM-encoded CA certificates to verify vault's TLS certificate",
		},

		// -client-cert
		&cli.StringFlag{
			Category:    strings.ToUpper(categoryHTTP),
			Destination: &cfg.HTTP.ClientCert,
			EnvVars:     []string{envPrefix + "CLIENT_CERT"},
			Name:        "client-cert",
			Usage:       "`path` to a single PEM-encoded CA certificate to use for TLS authentication to the vault",
		},

		// -client-key
		&cli.StringFlag{
			Category:    strings.ToUpper(categoryHTTP),
			Destination: &cfg.HTTP.ClientKey,
			EnvVars:     []string{envPrefix + "CLIENT_KEY"},
			Name:        "client-key",
			Usage:       "`path` to a single PEM-encoded private key matching the client certificate from -client-cert",
		},

		// -tls-server-name
		&cli.StringFlag{
			Category:    strings.ToUpper(categoryHTTP),
			Destination: &cfg.HTTP.TLSServerName,
			EnvVars:     []string{envPrefix + "TLS_SERVER_NAME"},
			Name:        "tls-server-name",
			Usage:       "`name` to use as the SNI host when connecting to the vault via TLS",
		},

		// -tls-skip-verify
		&cli.BoolFlag{
			Category:    strings.ToUpper(categoryHTTP),
			Destination: &cfg.HTTP.Insecure,
			EnvVars:     []string{envPrefix + "TLS_SKIP_VERIFY"},
			Name:        "tls-skip-verify",
			Usage:       "disable verification of TLS certificates",
		},
	}

	commands := []*cli.Command{
		CommandPlugin(cfg),
		CommandLogin(cfg),
		CommandQuote(cfg),
		CommandHelp(),
	}

	app := &cli.App{
		Name:    "vault-auth-plugin-attest",
		Usage:   "Attested authentication for Hashicorp Vault",
		Version: version,

		Commands:       commands,
		DefaultCommand: "plugin",

		Flags: slices.Concat(
			flagsHTTP,
		),
	}

	defer func() {
		zap.L().Sync() //nolint:errcheck
	}()
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed with error:\n\n%s\n\n", err.Error())
		os.Exit(1)
	}
}
