package logger

import (
	"go.uber.org/zap"
)

type Verbose struct{}

func V(lvl int) Verbose {
	return Verbose{}
}

func (v Verbose) Info(args ...interface{}) {
	zap.L().Sugar().WithOptions(zap.AddCallerSkip(1)).Debug(args...)
}

func (v Verbose) Infof(template string, args ...interface{}) {
	zap.L().Sugar().WithOptions(zap.AddCallerSkip(1)).Debugf(template, args...)
}
