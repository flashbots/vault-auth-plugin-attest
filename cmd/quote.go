package main

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/flashbots/vault-auth-plugin-attest/logger"
	"github.com/flashbots/vault-auth-plugin-attest/types"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func CommandQuote(cfg *config.Config) *cli.Command {
	cfg.TD = &config.TD{}

	flagsGeneral := []cli.Flag{
		&cli.StringFlag{ // --format
			Destination: &cfg.Format,
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
			Usage:       "attestation `type` (allowed values: tdx)",
			Value:       "tdx",
		},
	}

	return &cli.Command{
		Name:  "quote",
		Usage: "generate and print out attestation quote",

		Flags: slices.Concat(
			flagsGeneral,
			flagsTD,
		),

		Before: func(clictx *cli.Context) error {
			return cfg.Preprocess()
		},

		Action: func(_ *cli.Context) error {
			// setup

			if cfg.Verbose {
				l, err := logger.New()
				if err != nil {
					return err
				}
				zap.ReplaceGlobals(l)
			}

			// get quote

			switch cfg.TD.AttestationType {
			default:
				return fmt.Errorf("unknown attestation type: %s", cfg.TD.AttestationType)
			case "tdx":
				tdx, err := types.TDXFromQuote()
				if err != nil {
					return err
				}

				fmt.Printf("\n")
				fmt.Printf("Field                 Value\n")
				fmt.Printf("--------------------  ----------------------------------------------------------------\n")
				fmt.Printf("MROWNER:              %s\n", base64.StdEncoding.EncodeToString(tdx.MrOwner[:]))
				fmt.Printf("MROWNERCONFIG:        %s\n", base64.StdEncoding.EncodeToString(tdx.MrOwnerConfig[:]))
				fmt.Printf("MRCONFIGID:           %s\n", base64.StdEncoding.EncodeToString(tdx.MrConfigID[:]))
				fmt.Printf("MRTD:                 %s\n", base64.StdEncoding.EncodeToString(tdx.MrTD[:]))
				fmt.Printf("RTMR[0]:              %s\n", base64.StdEncoding.EncodeToString(tdx.RTMR0[:]))
				fmt.Printf("RTMR[1]:              %s\n", base64.StdEncoding.EncodeToString(tdx.RTMR1[:]))
				fmt.Printf("RTMR[2]:              %s\n", base64.StdEncoding.EncodeToString(tdx.RTMR2[:]))
				fmt.Printf("RTMR[3]:              %s\n", base64.StdEncoding.EncodeToString(tdx.RTMR3[:]))
				fmt.Printf("TUD.DEBUG:            %t\n", tdx.CheckDebug)
				fmt.Printf("SEC.SEPT_VE_DISABLE:  %t\n", tdx.CheckSeptVeDisable)
				fmt.Printf("\n")
			}
			return nil
		},
	}
}
