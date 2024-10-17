package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
