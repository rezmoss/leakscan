package scan

import "regexp"

// Rule: Regex needs exactly 1 capture group (secret).
// Keywords: lowercase prefilter before regex.
type Rule struct {
	ID           string
	Description  string
	Keywords     []string
	Regex        *regexp.Regexp
	CheckEntropy bool
}

var DefaultRules = []Rule{
	{
		ID:          "aws-access-key-id",
		Description: "AWS access key ID",
		Keywords:    []string{"akia", "asia"},
		Regex:       regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`),
	},
	{
		ID:          "github-token",
		Description: "GitHub personal access or app token",
		Keywords:    []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		Regex:       regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b`),
	},
	{
		ID:          "slack-token",
		Description: "Slack token",
		Keywords:    []string{"xox"},
		Regex:       regexp.MustCompile(`\b(xox[abposr]-[A-Za-z0-9-]{10,})`),
	},
	{
		ID:          "stripe-live-key",
		Description: "Stripe live secret or restricted key",
		Keywords:    []string{"sk_live_", "rk_live_"},
		Regex:       regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b`),
	},
	{
		ID:          "private-key",
		Description: "Private key block",
		Keywords:    []string{"private key"},
		Regex:       regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)`),
	},
	{
		ID:           "generic-secret",
		Description:  "Generic secret assigned to a key, token or password variable",
		Keywords:     []string{"key", "secret", "token", "passw"},
		Regex:        regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|passw(?:or)?d)\w*["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{8,})`),
		CheckEntropy: true,
	},
}
