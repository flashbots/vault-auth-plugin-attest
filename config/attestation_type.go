package config

import "slices"

const (
	AttestationTDX = "tdx"
)

var (
	AttestationTypes = []string{
		AttestationTDX,
	}
)

func attestationTypeIsValid(at string) bool {
	return slices.Contains(AttestationTypes, at)
}
