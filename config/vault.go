package config

import (
	"errors"
	"time"
)

type Vault struct {
	Address string        `yaml:"address"`
	NoPrint bool          `yaml:"no_print"`
	NoStore bool          `yaml:"no_store"`
	Timeout time.Duration `yaml:"timeout"`
}

var (
	errVaultCantCombineNoPrintAndNoStore = errors.New("flags --no-print and --no-store can not be combined")
)

func (cfg *Vault) Preprocess() error {
	{ // --vault-no-print && --vault-no-store
		if cfg.NoPrint && cfg.NoStore {
			return errVaultCantCombineNoPrintAndNoStore
		}
	}

	return nil
}
