package logger

import (
	"io"

	"go.uber.org/zap"
)

type Logger struct {
	log *zap.SugaredLogger
}

func Init(_ string, _, _ bool, _ io.Writer) *Logger {
	return &Logger{
		log: zap.L().Sugar(),
	}
}

func Warning(args ...interface{}) {
	zap.L().Sugar().WithOptions(zap.AddCallerSkip(1)).Warn(args)
}
