package utils

import "crypto/subtle"

// ConstantTimeMask returns 1 if logical AND of two slices is non zero and 0
// otherwise. The time taken is a function of the length of the slices and is
// independent of the contents. If the lengths of x and y do not match it
// returns 0 immediately.
func ConstantTimeMask(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}

	var v byte

	for i := 0; i < len(x); i++ {
		v |= x[i] & y[i]
	}

	return 1 - subtle.ConstantTimeByteEq(v, 0)
}
