package config

import "slices"

var (
	AttestationTypes = []string{
		"tdx",
		"tpm2",
	}
)

func attestationTypeIsValid(at string) bool {
	return slices.Contains(AttestationTypes, at)
}
