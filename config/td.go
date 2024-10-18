package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type TD struct {
	AttestationType string `yaml:"attestation_type"`
	Name            string `yaml:"name"`
	VaultPath       string `yaml:"vault_path"`
	TOTPSecret      string `yaml:"totp_secret"`
}

var (
	errTDAttestationTypeInvalid = errors.New("invalid attestation type")
	errTDTOTPSecretIsInvalid    = errors.New("invalid totp secret")
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
		if len(cfg.TOTPSecret) != 32 && len(cfg.TOTPSecret) != 0 {
			if info, err := os.Stat(cfg.TOTPSecret); err == nil && !info.IsDir() {
				if b, err := os.ReadFile(cfg.TOTPSecret); err == nil {
					cfg.TOTPSecret = strings.TrimSpace(string(b))
				}
			}
		}
		if len(cfg.TOTPSecret) != 32 && len(cfg.TOTPSecret) != 0 {
			return fmt.Errorf("%w: incorrect length: expected %d; got %d",
				errTDTOTPSecretIsInvalid, 32, len(cfg.TOTPSecret),
			)
		}
	}

	return nil
}
