package utils

import (
	"context"
	"fmt"
	"time"
)

func WithTimeout(
	ctx context.Context,
	timeout time.Duration,
	do func(context.Context) error,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	err := do(ctx)
	duration := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %v: %w", duration, err)
	}

	return err
}
