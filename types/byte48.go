package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
)

type Byte48 [48]byte

func (b Byte48) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		base64.StdEncoding.EncodeToString(b[:]),
	)
}

func (b *Byte48) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	res, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	if len(res) != 48 {
		return fmt.Errorf("invalid encoded length: expected 48, got %d", len(res))
	}
	copy(b[:], res)
	return nil
}

func (b Byte48) String() string {
	return base64.StdEncoding.EncodeToString(b[:])
}

func Byte48FromFieldData(
	data *framework.FieldData,
	key string,
	errs *multierror.Error,
) (*Byte48, bool, *multierror.Error) {
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

	if len(decoded) > 48 {
		return nil, false, multierror.Append(errs, fmt.Errorf(
			"data encoded by %s is longer than expected max 48 bytes: %d > 48", key, len(decoded),
		))
	}

	var res Byte48
	copy(res[:], decoded)

	return &res, true, errs
}
