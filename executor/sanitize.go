package executor

import (
	"regexp"
)

// sanitize strips secret-shaped substrings from an ansible
// playbook log before it leaves the customer's network. The
// goal is defensive: we don't know exactly what an
// ansible-playbook run will print, so we strip a broad set
// of patterns and rely on the playbook author to be the
// authoritative source for what's sensitive.
//
// Patterns covered:
//   - JSON-style: {"password": "supersecret123"} (closing
//     quote between key and colon)
//   - YAML/Ansible: password: foo / password = 'foo' /
//     password: 'foo'
//   - Compound env-var keys: DB_PASSWORD=hunter2 /
//     app_secret=xxx (prefix_ separator)
//   - Plain assignments: token=bar / api_key=baz /
//     bearer=qux
//   - PEM key blocks (multi-line, BEGIN..END)
//   - Authorization: Bearer XXX header values
//   - Long base64 (>= 32 chars) / hex (>= 32 chars) strings
//     (catches keys without a key= prefix)
//
// The replacement is `[REDACTED]` for each match. We do not
// preserve the original length (an attacker could use that
// to fingerprint the original secret type).
//
// Why a broad regex set (and not a per-customer config): the
// executor is the trust boundary. Defaulting to "strip
// anything that looks secret" is the safe side. False
// positives (stripping a non-secret) cost the operator a
// few extra minutes of log-reading time; false negatives
// (leaving a secret in) can be catastrophic. We pick the
// safe side.
func sanitize(s string) string {
	if s == "" {
		return s
	}

	patterns := []*regexp.Regexp{
		// Key=value (or key: value) with optional surrounding
		// quotes (JSON style). One pattern covers all of:
		// password=foo / password: foo / password: 'foo' /
		// "password": "foo" / DB_PASSWORD=hunter2 /
		// token=bar / api_key=baz / bearer=qux.
		secretKVPattern,
		// PEM key blocks (multi-line, handled as a single
		// sweep).
		pemBeginPattern,
		// Authorization header values: matches the
		// `Bearer XXX` portion so structured `curl -H
		// 'Authorization: Bearer eyJ...'` logs come out
		// readable.
		bearerPattern,
		// Long base64 / hex strings (>= 32 chars). Matches
		// strings that look like random keys (encrypted
		// tokens, JWT secrets, fingerprints).
		longB64Pattern,
		longHexPattern,
	}

	for _, p := range patterns {
		s = p.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// secretKVPattern is the consolidated "key = value"
// sanitizer. It handles:
//
//   - Quoted / unquoted values: `password=foo`,
//     `password: 'foo'`, `password: "foo"`
//   - JSON-style: `"password": "foo"` (closing quote
//     between key and colon — the `\b` word-boundary
//     accepts the quote as a non-word break)
//   - Compound prefixes: `DB_PASSWORD=hunter2`,
//     `app_secret=xxx`, `my-api-key=yyy` (zero or more
//     word-chars followed by an optional `_` or `-`)
//   - Bare keys: `password`, `token`, `api_key`,
//     `client_secret`, `bearer`
//   - Compound keys: `access_token`, `authorization_token`
//
// The pattern does NOT match `passwords` (plural) without
// `=` or `:`, so the words "password" / "secret" / "token"
// in non-secret contexts (docstrings, error messages) are
// preserved.
//
// The replacement is `[REDACTED]` (one per match), so an
// input like `password=foo token=bar` produces two
// `[REDACTED]` tokens.
var secretKVPattern = regexp.MustCompile(
	`(?i)\b` + // word boundary at start
		`(?:[A-Za-z0-9]+[_\-]?)?` + // optional compound prefix (DB_, app-, my_)
		`(` +
		`pass(?:word|wd)?|` + // password, passwd, pass, pwd
		`pwd|` + `token|` + `access[_\-]?token|` +
		`auth(?:orization)?[_\-]?token|` + `api[_\-]?key|` +
		`client[_\-]?secret|` + `secret|` + `bearer` + `)` +
		`"?` + `\s*[:=]\s*` +
		`(?:"[^"]*|'[^']*|\S+)`) // opening quote (no close) or bare value

// pemBeginPattern matches the start of a PEM-encoded private
// key. We strip the entire block (the next `-----END ...-----`
// line) so the sanitized log never contains the key bytes.
var pemBeginPattern = regexp.MustCompile(`-----BEGIN[ A-Z0-9_]*PRIVATE KEY[ A-Z0-9_]*-----[\s\S]*?-----END[ A-Z0-9_]*PRIVATE KEY[ A-Z0-9_]*-----`)

// bearerPattern matches `Bearer XXX` (case-insensitive).
// Used for `Authorization: Bearer XXX` header dumps.
var bearerPattern = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._\-+/=]+`)

// longB64Pattern matches base64-encoded strings of >= 32
// characters. Used to catch encrypted tokens, JWT secrets,
// etc. that don't have a `key=` prefix. Base64 alphabet:
// A-Z, a-z, 0-9, +, /, =.
var longB64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,2}`)

// longHexPattern matches hex strings of >= 32 characters.
// Used to catch API keys, fingerprints, etc. that are
// commonly encoded as hex.
var longHexPattern = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)

// SanitizationTestCases is a table-driven test surface
// (tested in sanitize_test.go). It documents the patterns
// the sanitizer is supposed to catch.
var SanitizationTestCases = []struct {
	Name  string
	Input string
	Want  string
}{
	{
		Name:  "ansible password assignment",
		Input: `TASK [Gathering Facts] ****\nok: [server1]\nTASK [Connect] ****\n{"password": "supersecret123", "host": "server1"}`,
		Want:  `TASK [Gathering Facts] ****\nok: [server1]\nTASK [Connect] ****\n{"[REDACTED]", "host": "server1"}`,
	},
	{
		Name:  "bearer token in curl",
		Input: `+ curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0' https://example.com`,
		Want:  `+ curl -H 'Authorization: [REDACTED]' https://example.com`,
	},
	{
		Name:  "private key block",
		Input: "config:\n  -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n  user: admin",
		Want:  "config:\n  [REDACTED]\n  user: admin",
	},
	{
		Name:  "no secrets",
		Input: `ok: [server1] => {"changed": false, "msg": "hello"}`,
		Want:  `ok: [server1] => {"changed": false, "msg": "hello"}`,
	},
	{
		Name:  "api_key with equals",
		Input: `api_key="abc123def456"`,
		// Regex consumes up to (but not including) the
		// closing quote of a quoted value, preserving it
		// for operator readability.
		Want: `[REDACTED]"`,
	},
	{
		Name:  "env var with secret value",
		Input: `Setting DB_PASSWORD=hunter2 in /etc/app.env`,
		Want:  `Setting [REDACTED] in /etc/app.env`,
	},
}
