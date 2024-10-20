package types

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"reflect"

	"github.com/flashbots/vault-auth-plugin-attest/utils"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdx "github.com/google/go-tdx-guest/client"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// TDX reflects our expectations about TDX trusted domain.
//
// For the reference see Intel TDX DCAP: Quote Generation Library and
// Quote Verification Library (rev 0.9, 2023/12).
type TDX struct {
	tokenutil.TokenParams `json:"-" mapstructure:"-" structs:"-"`

	// TOTPSecret is the secret used to generate initial TOTP codes.
	TOTPSecret string `json:"totp_secret" mapstructure:"-" structs:"-"`

	// MrOwner is the expected software-defined ID for the TD's owner.
	MrOwner *Byte48 `json:"tdx_mr_owner,omitempty" mapstructure:"tdx_mr_owner,omitempty" structs:"tdx_mr_owner,omitempty"`

	// MrOwnerConfig is the expected software-defined ID for owner-defined
	// configuration of the TD, e.g., specific to the workload rather than the
	// runtime or OS.
	MrOwnerConfig *Byte48 `json:"tdx_mr_owner_config,omitempty" mapstructure:"tdx_mr_owner_config,omitempty" structs:"tdx_mr_owner_config,omitempty"`

	// MrConfigID is the expected software-defined ID for non-owner-defined
	// configuration of the TD, e.g., runtime or OS configuration.
	MrConfigID *Byte48 `json:"tdx_mr_config_id,omitempty" mapstructure:"tdx_mr_config_id,omitempty" structs:"tdx_mr_config_id,omitempty"`

	// MrTD is the expected measurement of initial contents of the TD.
	MrTD *Byte48 `json:"tdx_mr_td,omitempty" mapstructure:"tdx_mr_td,omitempty" structs:"tdx_mr_td,omitempty"`

	// RTMR0 is the expected runtime-extendable measurement register #0.
	//
	// By convention, RTMR[0] is updated by the TD virtual firmware/BIOS (TDVF).
	// The measurements and the log file may differ depending on the TDVF
	// vendor. For more information on the measurements in RTMR[0], contact your
	// TDVF vendor.
	RTMR0 *Byte48 `json:"tdx_rtmr0,omitempty" mapstructure:"tdx_rtmr0,omitempty" structs:"tdx_rtmr0,omitempty"`

	// RTMR1 is the expected runtime-extendable measurement register #1.
	//
	// By convention, RTMR[1] is updated by the TD virtual firmware/BIOS (TDVF).
	// The measurements and the log file may differ depending on the TDVF
	// vendor. For more information on the measurements in RTMR[1], contact your
	// TDVF vendor.
	RTMR1 *Byte48 `json:"tdx_rtmr1,omitempty" mapstructure:"tdx_rtmr1,omitempty" structs:"tdx_rtmr1,omitempty"`

	// RTMR2 is the expected runtime-extendable measurement register #2.
	//
	// By convention, RTMR[2] measurements are generated by the OS. For more
	// information on this measurement, contact your OS vendor.
	RTMR2 *Byte48 `json:"tdx_rtmr2,omitempty" mapstructure:"tdx_rtmr2,omitempty" structs:"tdx_rtmr2,omitempty"`

	// RTMR3 is the expected runtime-extendable measurement register #3.
	//
	// By convention, RTMR[3] measurements are generated by runtime code. For
	// more information on this measurement, contact the TD workload owner.
	RTMR3 *Byte48 `json:"tdx_rtmr3,omitempty" mapstructure:"tdx_rtmr3,omitempty" structs:"tdx_rtmr3,omitempty"`

	// CheckTDAttrDebug indicates whether TUD.DEBUG == 0 is verified.
	//
	// TUD.DEBUG defines whether the TD runs in TD debug mode (set to 1) or not
	// (set to 0). In TD debug mode, the CPU state and private memory are
	// accessible by the host VMM.
	CheckDebug bool `json:"tdx_check_debug" mapstructure:"tdx_check_debug" structs:"tdx_check_debug"`

	// CheckTDAttrSeptVeDisable indicates whether SEC.SEPT_VE_DISABLE == 1 is
	// verified.
	//
	// SEC.SEPT_VE_DISABLE defines if EPT violation conversion to #VE on TD
	// access of PENDING pages is disabled.
	//
	// See also: https://intel.github.io/ccc-linux-guest-hardening-docs/security-spec.html#safety-against-ve-in-kernel-code
	CheckSeptVeDisable bool `json:"tdx_check_sept_ve_disable" mapstructure:"tdx_check_sept_ve_disable" structs:"tdx_check_sept_ve_disable"`

	// TODO: add XFAM?
}

var (
	errTDXQuoteIsNil                 = errors.New("quote is nil")
	errTDXQuoteMissingHeader         = errors.New("quote has no header")
	errTDXQuoteMissingBody           = errors.New("quote has no body")
	errTDXQuoteIsNotTDX              = errors.New("quote is not a tdx one")
	errTDXQuoteUnexpectedRTMRsCount  = errors.New("unexpected rtmrs count")
	errTDXQuoteUnexpectedTDAttrSize  = errors.New("unexpected size of td attributes")
	errTDXQuoteMismatchMrOwner       = errors.New("mr_owner mismatch")
	errTDXQuoteMismatchMrOwnerConfig = errors.New("mr_owner_config mismatch")
	errTDXQuoteMismatchMrConfigID    = errors.New("mr_config_id mismatch")
	errTDXQuoteMismatchMrTD          = errors.New("mr_td mismatch")
	errTDXQuoteMismatchRTMR0         = errors.New("rtmr[0] mismatch")
	errTDXQuoteMismatchRTMR1         = errors.New("rtmr[1] mismatch")
	errTDXQuoteMismatchRTMR2         = errors.New("rtmr[2] mismatch")
	errTDXQuoteMismatchRTMR3         = errors.New("rtmr[3] mismatch")
	errTDXQuoteUnderDebugDetected    = errors.New("td under debug detected")
	errTDXQuoteSeptVeDisableIsUnset  = errors.New("td sept_ve_disabled is unset")
	errTDXUnknownQuoteFormat         = errors.New("unknown tdx quote format")

	// all ints are little endian (least-significant byte is at the smallest address)

	maskDebug = Byte8{
		// 0     8    16    24    32    40    48    56
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	maskSeptVeDisable = Byte8{
		// 0     8    16    24    32    40    48    56
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
	}
)

func TDXFromQuote() (*TDX, error) {
	provider, err := tdx.GetQuoteProvider()
	if err != nil {
		return nil, err
	}

	rawQuote, err := tdx.GetRawQuote(provider, [64]byte{})
	if err != nil {
		return nil, err
	}

	_quote, err := tdxabi.QuoteToProto(rawQuote)
	if err != nil {
		return nil, err
	}

	quote := _quote.(*tdxpb.QuoteV4)
	if quote == nil {
		return nil, fmt.Errorf("%w: %s",
			errTDXUnknownQuoteFormat, reflect.TypeOf(_quote),
		)
	}

	if quote.TdQuoteBody == nil {
		return nil, errTDXQuoteMissingBody
	}

	body := quote.TdQuoteBody

	if len(body.Rtmrs) != 4 {
		return nil, fmt.Errorf("%w: %d != 4",
			errTDXQuoteUnexpectedRTMRsCount, len(body.Rtmrs),
		)
	}

	return &TDX{
		MrOwner:            (*Byte48)(body.MrOwner),
		MrOwnerConfig:      (*Byte48)(body.MrOwnerConfig),
		MrConfigID:         (*Byte48)(body.MrConfigId),
		MrTD:               (*Byte48)(body.MrTd),
		RTMR0:              (*Byte48)(body.Rtmrs[0]),
		RTMR1:              (*Byte48)(body.Rtmrs[1]),
		RTMR2:              (*Byte48)(body.Rtmrs[2]),
		RTMR3:              (*Byte48)(body.Rtmrs[3]),
		CheckDebug:         utils.ConstantTimeMask(maskDebug[:], body.TdAttributes) == 1,
		CheckSeptVeDisable: utils.ConstantTimeMask(maskSeptVeDisable[:], body.TdAttributes) == 1,
	}, nil
}

func (tdx *TDX) MatchesQuoteV4(quote *tdxpb.QuoteV4) ([]error, []error) {
	type test struct {
		expect *Byte48
		actual []byte
		err    error
	}

	{ // pre-flight checks
		if quote == nil {
			return []error{
				errTDXQuoteIsNil,
			}, nil
		}
		if quote.Header == nil {
			return []error{
				errTDXQuoteMissingHeader,
			}, nil
		}
		if quote.Header.TeeType != 0x81 {
			return []error{
				errTDXQuoteIsNotTDX,
			}, nil
		}
		if quote.TdQuoteBody == nil {
			return []error{
				errTDXQuoteMissingBody,
			}, nil
		}
		if len(quote.TdQuoteBody.Rtmrs) != 4 {
			return []error{
				fmt.Errorf("%w: %d != 4",
					errTDXQuoteUnexpectedRTMRsCount, len(quote.TdQuoteBody.Rtmrs),
				),
			}, nil
		}
		if len(quote.TdQuoteBody.TdAttributes) != 8 {
			return []error{
				fmt.Errorf("%w: %d != 8",
					errTDXQuoteUnexpectedTDAttrSize, len(quote.TdQuoteBody.TdAttributes),
				),
			}, nil
		}
	}

	body := quote.TdQuoteBody

	tests := []test{
		{ // mr_owner
			expect: tdx.MrOwner,
			actual: body.MrOwner,
			err:    errTDXQuoteMismatchMrOwner,
		},
		{ // mr_owner_config
			expect: tdx.MrOwnerConfig,
			actual: body.MrOwnerConfig,
			err:    errTDXQuoteMismatchMrOwnerConfig,
		},
		{ // tdx_mr_config_id
			expect: tdx.MrConfigID,
			actual: body.MrConfigId,
			err:    errTDXQuoteMismatchMrConfigID,
		},
		{ // mr_td
			expect: tdx.MrTD,
			actual: body.MrTd,
			err:    errTDXQuoteMismatchMrTD,
		},
		{ // rtmr0
			expect: tdx.RTMR0,
			actual: body.Rtmrs[0],
			err:    errTDXQuoteMismatchRTMR0,
		},
		{ // rtmr1
			expect: tdx.RTMR1,
			actual: body.Rtmrs[1],
			err:    errTDXQuoteMismatchRTMR1,
		},
		{ // rtmr2
			expect: tdx.RTMR2,
			actual: body.Rtmrs[2],
			err:    errTDXQuoteMismatchRTMR2,
		},
		{ // rtmr3
			expect: tdx.RTMR3,
			actual: body.Rtmrs[3],
			err:    errTDXQuoteMismatchRTMR3,
		},
	}

	errs := make([]error, 0, len(tests)+2)
	dump := make([]error, 0, len(tests)+2)

	{ // report fields
		dummy := Byte48{}
		for _, t := range tests {
			// make sure the time is constant regardless of the config
			if t.expect != nil {
				if subtle.ConstantTimeCompare(t.expect[:], t.actual) != 1 {
					errs = append(errs, t.err)
				} else {
					errs = append(errs, nil)
				}
			} else {
				if subtle.ConstantTimeCompare(dummy[:], t.actual) != 1 {
					dump = append(dump, t.err)
				} else {
					errs = append(errs, nil)
				}
			}
		}
	}

	{ // report attributes
		if tdx.CheckDebug {
			if utils.ConstantTimeMask(maskDebug[:], body.TdAttributes) == 1 {
				errs = append(errs, errTDXQuoteUnderDebugDetected)
			} else {
				errs = append(errs, nil)
			}
		} else {
			if utils.ConstantTimeMask(maskDebug[:], body.TdAttributes) == 1 {
				dump = append(errs, errTDXQuoteUnderDebugDetected)
			} else {
				dump = append(errs, nil)
			}
		}

		if tdx.CheckSeptVeDisable {
			if utils.ConstantTimeMask(maskSeptVeDisable[:], body.TdAttributes) == 0 {
				errs = append(errs, errTDXQuoteSeptVeDisableIsUnset)
			} else {
				errs = append(errs, nil)
			}
		} else {
			if utils.ConstantTimeMask(maskSeptVeDisable[:], body.TdAttributes) == 0 {
				dump = append(errs, errTDXQuoteSeptVeDisableIsUnset)
			} else {
				dump = append(errs, nil)
			}
		}
	}

	return errs, dump
}
