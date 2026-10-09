package executor

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// newLogger builds the structured JSON logger. All records
// (INFO+ / WARN+ / ERROR+) are written to stdout — the standard
// daemon convention (`my-daemon > /var/log/my-daemon.log 2>&1`).
// Customers who want to split WARN/ERROR can filter on the
// `level` JSON field downstream.
//
// Why JSON (not text): every other SentraOps component logs
// structured JSON. The executor matches the rest of the platform
// so customers running a single log pipeline for SentraOps don't
// need a separate parser for the executor.
func newLogger(stdout *os.File) *logrus.Logger {
	log := logrus.New()
	log.SetOutput(stdout)
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "ts",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "msg",
		},
	})
	return log
}

// applyLogLevel parses the textual log level string and sets it
// on the logger. The string is matched against the same
// case-insensitive set Config.validate accepts.
func applyLogLevel(log *logrus.Logger, level string) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info", "":
		log.SetLevel(logrus.InfoLevel)
	case "warn", "warning":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		// validate() already rejected unknown values; this is a
		// defense-in-depth fallback. Default to info.
		log.SetLevel(logrus.InfoLevel)
	}
}
