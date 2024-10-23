package plugin

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type TD interface {
	AttestationType() string
	GetName() string

	GetTOTPSecret() string
	SetTOTPSecret(string)

	ParseTokenFields(*logical.Request, *framework.FieldData) error
	PopulateTokenData(map[string]interface{})
}
