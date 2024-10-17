package main

import (
	"github.com/urfave/cli/v2"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/flashbots/vault-auth-plugin-attest/vault/plugin"
)

func CommandPlugin(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:  "plugin",
		Usage: "run attested auth plugin",

		Action: func(_ *cli.Context) error {
			return plugin.ServeMultiplex(cfg)
		},
	}
}
