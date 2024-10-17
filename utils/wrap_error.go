package utils

import "fmt"

func WrapError[T any](wrap error, do func() (T, error)) (T, error) {
	res, err := do()
	if err != nil {
		var zero T
		return zero, fmt.Errorf("%w: %w", wrap, err)
	}
	return res, nil
}
