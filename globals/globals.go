package globals

import (
	"time"

	"github.com/pquerna/otp"
)

const (
	NoncePeriod = 15 * time.Second

	TOTPAlgorithm = otp.AlgorithmSHA256
	TOTPDigits    = 8
	TOTPPeriod    = 1 * time.Second // note: this must be in whole seconds

	TDXNonceSize  = 64
	TPM2NonceSize = 20 // some TPMs don't support nonces longer than 20 bytes
)
