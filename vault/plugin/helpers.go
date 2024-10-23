package plugin

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/logical"
)

// sanitise should be used for unauthenticated paths:
//
//   - When underlying wrapped call returns with success, it will just relay the
//     response as-is.
//
//   - When underlying wrapped call fails, it will mask the response with a
//     generic one and wait for a constant timeout (as a form of naïve
//     rate-limiting as well as a precaution against time-bound
//     data-extraction).
func (b *backend) sanitise(
	do func() (*logical.Response, error),
) (*logical.Response, error) {
	ts := time.Now()

	res, err := do()

	time.Sleep(time.Until(ts.Add(time.Second)))

	if err == nil {
		return res, nil
	}

	return logical.ErrorResponse(logical.ErrInvalidRequest.Error()), logical.ErrInvalidRequest
}

// multierror creates multierror.Error that is convenient for the logs (prints
// out as a single line of text instead of multiple).
func (b *backend) multierror(errs ...error) *multierror.Error {
	err := &multierror.Error{
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
	return multierror.Append(err, errs...)
}
