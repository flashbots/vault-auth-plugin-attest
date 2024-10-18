package plugin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/flashbots/vault-auth-plugin-attest/globals"
	"github.com/flashbots/vault-auth-plugin-attest/types"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pquerna/otp/totp"

	tdxabi "github.com/google/go-tdx-guest/abi"
	txdcheck "github.com/google/go-tdx-guest/proto/checkconfig"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
)

const helpTDXLoginSynopsys = `
Log in with TOTP code and attestation quote.
`

const helpTDXLoginDescription = `
This endpoint authenticates using TOTP code and attestation quote.
`

var (
	errTDXUnexpectedNonce = errors.New("unexpected nonce")
)

func pathTDXLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "tdx/" + framework.GenericNameRegex("name") + "/login",
		HelpSynopsis:    helpTDXLoginSynopsys,
		HelpDescription: helpTDXLoginDescription,

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "TDX trusted domain name",
			},

			"totp": {
				Type:        framework.TypeString,
				Description: "TOTP code",
			},

			"quote": {
				Type:        framework.TypeString,
				Description: "TDX attestation quote",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTDXLogin,
			},
		},
	}
}

func (b *backend) pathTDXLogin(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	var (
		name    string
		tdx     *types.TDX
		quote   any
		quoteV4 *tdxpb.QuoteV4
		err     error
	)

	l := b.Logger()

	{ // fetch the storage
		name = data.Get("name").(string)
		if name == "" {
			return b.invalidRequest("tdx domain name is required")
		}

		tdx, err = b.loadTDX(ctx, req.Storage, name)
		if err != nil {
			return b.loggedError("failed to load tdx domain from storage",
				"domain", name,
				"error", err,
			)
		}
		if tdx == nil {
			return b.invalidRequest("tdx domain is not configured: %s",
				name,
			)
		}
	}

	{ // parse tdx quote
		quoteBase64 := data.Get("quote").(string)
		if quoteBase64 == "" {
			return b.invalidRequest("tdx quote is required")
		}

		quoteBytes, err := base64.StdEncoding.DecodeString(quoteBase64)
		if err != nil {
			return b.loggedError("failed to base64-decode tdx quote",
				"domain", name,
				"error", err,
			)
		}

		quote, err = tdxabi.QuoteToProto(quoteBytes)
		if err != nil {
			return b.loggedError("failed to abi-parse tdx quote",
				"domain", name,
				"error", err,
			)
		}

		quoteV4 = quote.(*tdxpb.QuoteV4)
		if quoteV4 == nil {
			return b.loggedError("unknown tdx quote format",
				"domain", name,
			)
		}
	}

	{ // validate totp code
		l.Debug("validating totp code for tdx login")

		totpCode := data.Get("totp").(string)
		if totpCode == "" {
			return b.invalidRequest("totp code is required")
		}

		valid, err := totp.ValidateCustom(totpCode, tdx.TOTPSecret, time.Now().UTC(), b.totpOptions)
		if err != nil {
			return b.loggedError("failed to validate totp code",
				"domain", name,
				"error", err,
			)
		}
		if !valid {
			return b.loggedError("totp code is invalid",
				"domain", name,
			)
		}

		entry := name + "/totp/" + totpCode

		if _, used := b.totpUsedCodes.Get(entry); used {
			return b.loggedError("totp code was already used",
				"domain", name,
			)
		}
		if err := b.totpUsedCodes.Add(entry, nil, 3*globals.TOTPPeriod); err != nil {
			return b.loggedError("failed to validate totp code",
				"domain", name,
				"error", err,
			)
		}
	}

	errs := &multierror.Error{
		ErrorFormat: func(es []error) string {
			if len(es) == 1 {
				return es[0].Error()
			}

			points := make([]string, len(es))
			for i, err := range es {
				points[i] = err.Error()
			}

			return fmt.Sprintf(
				"%d errors occurred: %s",
				len(es), strings.Join(points, "; "))
		},
	}

	{ // validate tdx quote
		sopts, err := tdxverify.RootOfTrustToOptions(
			&txdcheck.RootOfTrust{}, // TODO: make configurable
		)
		if err != nil {
			return b.loggedError("failed to validate tdx quote",
				"domain", name,
				"error", err,
			)
		}
		sopts.Getter = &tdxtrust.RetryHTTPSGetter{
			Getter: &tdxtrust.SimpleHTTPSGetter{},
		}
		errs = multierror.Append(errs, tdxverify.TdxQuote(quote, sopts))
	}

	{ // verify the nonce
		quoteNonce := base64.StdEncoding.EncodeToString(quoteV4.TdQuoteBody.ReportData)
		entry := name + "/nonce/" + quoteNonce
		if _, present := b.totpUsedCodes.Get(entry); present {
			errs = multierror.Append(errs, nil)
		} else {
			errs = multierror.Append(errs, errTDXUnexpectedNonce)
		}
	}

	{ // verify tdx quote
		reported, ignored := tdx.MatchesQuoteV4(quoteV4)

		errs = multierror.Append(errs, reported...)

		if err := errs.ErrorOrNil(); err != nil {
			return b.loggedError("failed to validate tdx quote",
				"domain", name,
				"error", err,
				"ignoreme", len(ignored), // avoid compiler optimising things out
			)
		}
	}

	{ // return result
		auth := &logical.Auth{
			Metadata: map[string]string{
				"tdx": name,
			},
			Alias: &logical.Alias{
				Name: name,
			},
		}
		tdx.PopulateTokenAuth(auth)

		return &logical.Response{
			Auth: auth,
		}, nil
	}
}
