package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

type TD struct {
	AttestationType   string `yaml:"attestation_type"`
	Name              string `yaml:"name"`
	VaultPath         string `yaml:"vault_path"`
	TOTPSecret        string `yaml:"totp_secret"`
	TPM2AKPrivateBlob string `yaml:"tpm2_ak_private_blob"`
}

var (
	errTDAttestationTypeInvalid = errors.New("invalid attestation type")
	errTDTOTPSecretIsInvalid    = errors.New("invalid totp secret")
	errTDTPM2AKPrivateBlob      = errors.New("invalid tpm2 attestation key private blob")
)

func (cfg *TD) Preprocess() error {
	{ // --td-attestation-type
		if !attestationTypeIsValid(cfg.AttestationType) {
			return fmt.Errorf("%w: expected '%s'; got '%s'",
				errTDAttestationTypeInvalid,
				strings.Join(AttestationTypes, "', '"),
				cfg.AttestationType,
			)
		}
	}

	{ // --td-totp-secret
		if _, err := base64.StdEncoding.DecodeString(cfg.TOTPSecret); err != nil {
			if info, err := os.Stat(cfg.TOTPSecret); err == nil && !info.IsDir() {
				if b, err := os.ReadFile(cfg.TOTPSecret); err == nil {
					cfg.TOTPSecret = strings.TrimSpace(string(b))
				}
			}
		}
		if _, err := base64.StdEncoding.DecodeString(cfg.TOTPSecret); err != nil {
			return fmt.Errorf("%w: %w",
				errTDTOTPSecretIsInvalid, err,
			)
		}
	}

	{ // --td-tpm2-ak-private-blob
		if cfg.AttestationType == "tpm2" {
			if _, err := base64.StdEncoding.DecodeString(cfg.TPM2AKPrivateBlob); err != nil {
				if info, err := os.Stat(cfg.TPM2AKPrivateBlob); err == nil && !info.IsDir() {
					if b, err := os.ReadFile(cfg.TPM2AKPrivateBlob); err == nil {
						cfg.TPM2AKPrivateBlob = strings.TrimSpace(string(b))
					}
				}
			}
			if _, err := base64.StdEncoding.DecodeString(cfg.TPM2AKPrivateBlob); err != nil {
				return fmt.Errorf("%w: %w",
					errTDTPM2AKPrivateBlob, err,
				)
			}
		}
	}

	return nil
}
