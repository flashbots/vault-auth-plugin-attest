package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	vaultcmd "github.com/hashicorp/vault/command"
)

type Config struct {
	TD *TD `yaml:"trusted_domain"`

	HTTP  *HTTP  `yaml:"http"`
	Vault *Vault `yaml:"vault"`

	Format  string `yaml:"-"`
	Version string `yaml:"-"`
	Verbose bool   `yaml:"-"`
}

var (
	Formats = slices.Collect(maps.Keys(
		vaultcmd.Formatters,
	))
)

func (cfg *Config) Preprocess() error {
	errs := make([]error, 0)

	if cfg.Format == "" {
		cfg.Format = "table"
	}
	if !slices.Contains(Formats, cfg.Format) {
		errs = append(errs, fmt.Errorf("invalid format %s (allowed values: %s)",
			cfg.Format,
			strings.Join(Formats, ", "),
		))
	}

	if err := cfg.HTTP.Preprocess(); err != nil {
		errs = append(errs, err)
	}

	if err := cfg.TD.Preprocess(); err != nil {
		errs = append(errs, err)
	}

	if err := cfg.Vault.Preprocess(); err != nil {
		errs = append(errs, err)
	}

	switch len(errs) {
	default:
		return errors.Join(errs...)
	case 1:
		return errs[0]
	case 0:
		return nil
	}
}
