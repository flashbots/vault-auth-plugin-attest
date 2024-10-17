package logger

import "go.uber.org/zap"

type Verbose struct {
	log *zap.SugaredLogger
}

func V(lvl int) Verbose {
	return Verbose{
		log: zap.L().Sugar(),
	}
}

func (v Verbose) Info(args ...interface{}) {
	v.log.WithOptions(zap.AddCallerSkip(1)).Debug(args...)
}

func (v Verbose) Infof(template string, args ...interface{}) {
	v.log.WithOptions(zap.AddCallerSkip(1)).Debugf(template, args...)
}
