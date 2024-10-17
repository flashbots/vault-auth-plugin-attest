package logger

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	ErrLoggerFailedToBuild = errors.New("failed to build the logger")
)

type contextKey string

const loggerContextKey contextKey = "logger"

func ContextWith(parent context.Context, logger *zap.Logger) context.Context {
	return context.WithValue(parent, loggerContextKey, logger)
}

func FromContext(ctx context.Context) *zap.Logger {
	if l, found := ctx.Value(loggerContextKey).(*zap.Logger); found {
		return l
	}
	return zap.L()
}

func New() (*zap.Logger, error) {
	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapcore.DebugLevel),
		Development:      true,
		Encoding:         "console",
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},

		EncoderConfig: zapcore.EncoderConfig{
			EncodeTime: zapcore.ISO8601TimeEncoder,
			LineEnding: zapcore.DefaultLineEnding,
			MessageKey: "M",
			TimeKey:    "T",
		},
	}

	l, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("%w: %w",
			ErrLoggerFailedToBuild, err,
		)
	}

	return l, nil
}
