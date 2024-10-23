package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
)

type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		base64.StdEncoding.EncodeToString(b),
	)
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	res, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	*b = (*b)[:0]
	*b = append(*b, res...)

	return nil
}

func (b Bytes) String() string {
	return base64.StdEncoding.EncodeToString(b)
}

func BytesFromFieldData(
	data *framework.FieldData,
	key string,
	errs *multierror.Error,
) (Bytes, bool, *multierror.Error) {
	encoded, present, err := data.GetOkErr(key)
	if err != nil {
		return nil, false, multierror.Append(err, errs)
	}
	if !present {
		return nil, false, errs
	}

	encodedStr, ok := encoded.(string)
	if !ok {
		return nil, false, multierror.Append(errs, fmt.Errorf(
			"%s is not encoded as base64 string", key,
		))
	}

	if encodedStr == "" {
		return nil, true, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return nil, false, multierror.Append(errs, fmt.Errorf(
			"%s is not encoded as base64 string: %w", key, err,
		))
	}

	res := Bytes(decoded)

	return res, true, nil
}
