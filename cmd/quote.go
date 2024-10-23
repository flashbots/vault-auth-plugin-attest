package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/flashbots/vault-auth-plugin-attest/config"
	"github.com/flashbots/vault-auth-plugin-attest/logger"
	"github.com/flashbots/vault-auth-plugin-attest/tdx"
	"github.com/flashbots/vault-auth-plugin-attest/tpm2"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func CommandQuote(cfg *config.Config) *cli.Command {
	flagsGeneral := []cli.Flag{
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
			Usage:       "attestation `type` (allowed values: " + strings.Join(config.AttestationTypes, ", ") + ")",
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
				td, err := tdx.FromPlatform()
				if err != nil {
					return err
				}
				fmt.Printf("\n")
				fmt.Printf("Field                 Value\n")
				fmt.Printf("--------------------  ----------------------------------------------------------------\n")
				fmt.Printf("MROWNER:              %s\n", td.MrOwner)
				fmt.Printf("MROWNERCONFIG:        %s\n", td.MrOwnerConfig)
				fmt.Printf("MRCONFIGID:           %s\n", td.MrConfigID)
				fmt.Printf("MRTD:                 %s\n", td.MrTD)
				fmt.Printf("RTMR[0]:              %s\n", td.RTMR0)
				fmt.Printf("RTMR[1]:              %s\n", td.RTMR1)
				fmt.Printf("RTMR[2]:              %s\n", td.RTMR2)
				fmt.Printf("RTMR[3]:              %s\n", td.RTMR3)
				fmt.Printf("TUD.DEBUG:            %t\n", td.CheckDebug)
				fmt.Printf("SEC.SEPT_VE_DISABLE:  %t\n", td.CheckSeptVeDisable)
				fmt.Printf("\n")

			case "tpm2":
				td, err := tpm2.FromPlatform()
				if err != nil {
					return err
				}
				akPublic := td.AKPublic.String()
				akPrivateBlob := td.AKPrivateBlob.String()
				fmt.Printf("\n")
				fmt.Printf("Field        Value\n")
				fmt.Printf("-----------  ----------------------------------------------------------------\n")
				fmt.Printf("AKPub:       %s\n", akPublic[:64])
				for pos := 64; pos < len(akPublic); pos += 64 {
					fmt.Printf("             %s\n", akPublic[pos:min(pos+64, len(akPublic))])
				}
				fmt.Printf("AKPrivBlob:  %s\n", akPrivateBlob[:64])
				for pos := 64; pos < len(akPrivateBlob); pos += 64 {
					fmt.Printf("             %s\n", akPrivateBlob[pos:min(pos+64, len(akPrivateBlob))])
				}
				for idx, pcr := range td.PCRs {
					if pcr != nil {
						fmt.Printf("PCR[%02d]:     %s\n", idx, pcr)
					}
				}
			}

			return nil
		},
	}
}
