package executor

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestNewLoggerJSONOutput verifies the logger emits structured
// JSON. Critical for SIEM integration: a customer running a
// single log pipeline for SentraOps cannot have a separate
// text-only parser for the executor.
func TestNewLoggerJSONOutput(t *testing.T) {
	stdout := tempFile(t)
	defer stdout.Close()

	logger := newLogger(stdout)
	logger.Info("hello world")

	rawStdout, err := readFile(stdout)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if len(rawStdout) == 0 {
		t.Fatal("stdout empty; expected the INFO line")
	}
	var got map[string]any
	if err := json.Unmarshal(rawStdout, &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout = %q", err, string(rawStdout))
	}
	if got["msg"] != "hello world" {
		t.Errorf("msg = %v, want 'hello world'", got["msg"])
	}
	if got["level"] != "info" {
		t.Errorf("level = %v, want 'info'", got["level"])
	}
	if _, ok := got["ts"]; !ok {
		t.Error("JSON log record missing 'ts' field (FieldMap should rename 'time' -> 'ts')")
	}
}

// TestNewLoggerAllLevelsToStdout pins the daemon convention:
// every level (INFO / WARN / ERROR) goes to the single stdout
// stream. Downstream consumers (SIEM, journalctl, log shipper)
// filter on the `level` JSON field. Splitting stdout vs stderr
// per level is over-engineered for the skeleton and creates
// observability surprises in containerized deployments.
func TestNewLoggerAllLevelsToStdout(t *testing.T) {
	stdout := tempFile(t)
	defer stdout.Close()

	logger := newLogger(stdout)
	logger.Info("info line")
	logger.Warn("warn line")
	logger.Error("error line")

	rawStdout, _ := readFile(stdout)
	lines := strings.Split(strings.TrimRight(string(rawStdout), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("stdout has %d lines, want 3 (INFO + WARN + ERROR)", len(lines))
	}
	for i, wantLevel := range []string{"info", "warning", "error"} {
		var got map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &got); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i, err)
		}
		if got["level"] != wantLevel {
			t.Errorf("line %d level = %v, want %q", i, got["level"], wantLevel)
		}
	}
}

// TestApplyLogLevel verifies the level string -> logrus level
// mapping. Match the case-insensitive set Config.validate accepts.
func TestApplyLogLevel(t *testing.T) {
	tests := []struct {
		in   string
		want logrus.Level
	}{
		{"debug", logrus.DebugLevel},
		{"DEBUG", logrus.DebugLevel},
		{"info", logrus.InfoLevel},
		{"", logrus.InfoLevel}, // empty defaults to info
		{"warn", logrus.WarnLevel},
		{"warning", logrus.WarnLevel},
		{"WARN", logrus.WarnLevel},
		{"error", logrus.ErrorLevel},
		{"ERROR", logrus.ErrorLevel},
		{"verbose", logrus.InfoLevel}, // unknown -> default to info
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			logger := logrus.New()
			applyLogLevel(logger, tc.in)
			if logger.GetLevel() != tc.want {
				t.Errorf("applyLogLevel(%q): level = %v, want %v",
					tc.in, logger.GetLevel(), tc.want)
			}
		})
	}
}

// tempFile returns a *os.File in the test temp dir that the
// logger can write to. The test reads from it via readFile.
// Auto-removed when t.TempDir()'s Cleanup fires.
//
// Why not os.Stdout directly: CI runs the tests in parallel; we
// don't want to interleave the executor's log output with the
// test runner's own output.
func tempFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "executor-log-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	return f
}

// readFile reads the current contents of f and rewinds it. The
// logger appended to f; we read what it wrote.
func readFile(f *os.File) ([]byte, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}
