// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// Simple zap-based logger - NO GOLEM DEPENDENCY
// Licensed under the Apache License, Version 2.0

package ledger

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var log *zap.SugaredLogger

func init() {
	initLogger()
}

func initLogger() {
	level := getLogLevel()

	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	switch level {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, _ := config.Build()
	log = logger.Sugar()
}

func getLogLevel() string {
	level := os.Getenv("LEDGER_LOG_LEVEL")
	if level == "" {
		level = "info"
	}
	return strings.ToLower(level)
}
