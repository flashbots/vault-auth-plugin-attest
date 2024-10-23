package tpm2

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/flashbots/vault-auth-plugin-attest/types"
	"github.com/google/go-attestation/attest"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
)

type TPM2 struct {
	tokenutil.TokenParams `json:"-" mapstructure:"-" structs:"-"`

	// Name is the name of trusted domain.
	Name string `json:"-" mapstructure:"-" structs:"-"`

	// TOTPSecret is the secret used to generate initial TOTP codes.
	TOTPSecret string `json:"totp_secret" mapstructure:"totp_secret" structs:"totp_secret"`

	// AKPublic is the public part of the attestation key used to generate
	// TPM 2.0 attestations/quotes.
	AKPublic types.Bytes `json:"tpm2_ak_public" mapstructure:"tpm2_ak_public" structs:"tpm2_ak_public"`

	// AKPrivateBlob is the binary blob that is used to re-load the attestation
	// key into TPM so that required attestation/quote can be generated.
	AKPrivateBlob types.Bytes `json:"-" mapstructure:"-" structs:"-"`

	// PCRs is the slice with expected values of SHA256 Platform Configuration
	// Registers.
	PCRs [24]*types.Byte32 `json:"tpm2_pcrs,omitempty" mapstructure:"-" structs:"-"`
}

var (
	errTPM2UnexpectedVersion              = errors.New("unexpected tpm version detected")
	errTPM2AttestationIsNil               = errors.New("tpm2 attestation is nit")
	errTPM2AttestationDuplicateIndex      = errors.New("duplicate pcr index in tpm2 attestation")
	errTPM2AttestationPCRIndexOutOfBounds = errors.New("pcr index out of bounds in tpm2 attestation")
	errTPM2AttestationPCRMismatch         = errors.New("tpm2 pcr digest mismatch")
)

// FromPlatform creates new TPM2 instance from the parameters of the platform
// we are currently running on.
func FromPlatform() (*TPM2, error) {
	provider, err := attest.OpenTPM(&attest.OpenConfig{})
	if err != nil {
		return nil, err
	}
	defer provider.Close()

	ak, err := provider.NewAK(nil)
	if err != nil {
		return nil, err
	}
	defer ak.Close(provider)

	akPrivateBlob, err := ak.Marshal()
	if err != nil {
		return nil, err
	}

	attestation, err := provider.AttestPlatform(ak, nil, nil)
	if err != nil {
		return nil, err
	}

	if attestation.TPMVersion != attest.TPMVersion20 {
		return nil, fmt.Errorf("%w: %d != %d",
			errTPM2UnexpectedVersion, attestation.TPMVersion, attest.TPMVersion20,
		)
	}

	pcrs := [24]*types.Byte32{}
	for _, pcr := range attestation.PCRs {
		if pcr.DigestAlg != crypto.SHA256 {
			continue
		}
		pcrs[pcr.Index] = (*types.Byte32)(pcr.Digest)
	}

	return &TPM2{
		AKPublic:      attestation.Public,
		AKPrivateBlob: akPrivateBlob,
		PCRs:          pcrs,
	}, nil
}

func (td *TPM2) MatchesAttestation(attestation *attest.PlatformParameters) (
	[]error, []error,
) {
	pcrs := make([]*[]byte, 24)

	{ // pre-flight
		if attestation == nil {
			return []error{
				errTPM2AttestationIsNil,
			}, nil
		}
		if attestation.TPMVersion != attest.TPMVersion20 {
			return []error{
				fmt.Errorf("%w: %d != %d",
					errTPM2UnexpectedVersion, attestation.TPMVersion, attest.TPMVersion20,
				),
			}, nil
		}
		for _, pcr := range attestation.PCRs {
			if pcr.DigestAlg == crypto.SHA256 {
				if pcr.Index < 0 || pcr.Index >= 24 {
					return []error{
						fmt.Errorf("%w: %d",
							errTPM2AttestationPCRIndexOutOfBounds, pcr.Index,
						),
					}, nil
				}
				if pcrs[pcr.Index] != nil {
					return []error{
						fmt.Errorf("%w: %d",
							errTPM2AttestationDuplicateIndex, pcr.Index,
						),
					}, nil
				}
				pcrs[pcr.Index] = &pcr.Digest
			}
		}
		dummy := make([]byte, 32)
		for idx := 0; idx < 24; idx++ {
			if pcrs[idx] == nil {
				pcrs[idx] = &dummy
			}
		}
	}

	errs := make([]error, 0, 24)
	dump := make([]error, 0, 24)

	{ // pcrs
		dummy := &types.Byte32{}
		for idx, actual := range pcrs {
			err := fmt.Errorf("%w: %d", errTPM2AttestationPCRMismatch, idx)
			if expect := td.PCRs[idx]; expect != nil {
				if subtle.ConstantTimeCompare(expect[:], *actual) != 1 {
					errs = append(errs, err)
				} else {
					errs = append(errs, nil)
				}
			} else {
				if subtle.ConstantTimeCompare(dummy[:], *actual) != 1 {
					dump = append(dump, err)
				} else {
					dump = append(dump, nil)
				}
			}
		}
	}

	return errs, dump
}

func (td *TPM2) GetName() string {
	return td.Name
}

func (td *TPM2) AttestationType() string {
	return "tpm2"
}

func (td *TPM2) GetTOTPSecret() string {
	return td.TOTPSecret
}

func (td *TPM2) SetTOTPSecret(totpSecret string) {
	td.TOTPSecret = totpSecret
}
