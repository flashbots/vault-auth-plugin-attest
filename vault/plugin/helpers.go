package plugin

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/flashbots/vault-auth-plugin-attest/types"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// loggedError logs an error and returns vault's logical error response to the
// client.
//
// The error is logged with all provisioned key/value pairs, but only the
// text message of the error is returned to the client (to prevent leaking
// internal and potentially sensitive data).
func (b *backend) loggedError(
	text string,
	args ...interface{},
) (*logical.Response, error) {
	l := b.Logger()
	l.Error(text, args...)
	return logical.ErrorResponse(text), errors.New(text)
}

// invalidRequest logs an error and returns vault's logical error response to the
// client.
//
// The error text is rendered with printf first, and then used for both: the
// log message as well as the message returned to the client.
func (b *backend) invalidRequest(
	text string,
	args ...interface{},
) (*logical.Response, error) {
	l := b.Logger()
	msg := fmt.Sprintf(text, args...)
	l.Error(msg)
	return logical.ErrorResponse(msg), errors.New(msg)
}

func extractByte48(
	data *framework.FieldData,
	key string,
	errs *multierror.Error,
) (*types.Byte48, *multierror.Error) {
	encoded, present, err := data.GetOkErr(key)
	if err != nil {
		return nil, multierror.Append(err, errs)
	}
	if !present {
		return nil, errs
	}

	encodedStr, ok := encoded.(string)
	if !ok {
		return nil, multierror.Append(errs, fmt.Errorf(
			"%s is not encoded as base64 string", key,
		))
	}

	decoded, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return nil, multierror.Append(errs, fmt.Errorf(
			"%s is not encoded as base64 string: %w", key, err,
		))
	}

	if len(decoded) > 48 {
		return nil, multierror.Append(errs, fmt.Errorf(
			"data encoded by %s is longer than expected max 48 bytes: %d > 48", key, len(decoded),
		))
	}

	var res types.Byte48
	copy(res[:], decoded)

	return &res, errs
}
