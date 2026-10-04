package scan

import (
	"regexp"
	"slices"
	"strings"
)

// DefaultMinEntropy: min for CheckEntropy rules.
const DefaultMinEntropy = 3.5

type Match struct {
	Rule   *Rule
	Secret string
	Column int

	start, end int
}

type Detector struct {
	Rules      []Rule
	MinEntropy float64
}

func NewDetector() *Detector {
	return &Detector{Rules: DefaultRules, MinEntropy: DefaultMinEntropy}
}

// Find: span reported once, so specific rules go before generic.
func (d *Detector) Find(line string) []Match {
	lower := strings.ToLower(line)
	var matches []Match
	for i := range d.Rules {
		r := &d.Rules[i]
		if !slices.ContainsFunc(r.Keywords, func(k string) bool { return strings.Contains(lower, k) }) {
			continue
		}
		for _, loc := range r.Regex.FindAllStringSubmatchIndex(line, -1) {
			start, end := loc[2], loc[3]
			if overlaps(matches, start, end) {
				continue
			}
			secret := line[start:end]
			if r.CheckEntropy && (Entropy(secret) < d.MinEntropy || looksLikeCode(line, start, end)) {
				continue
			}
			matches = append(matches, Match{Rule: r, Secret: secret, Column: start + 1, start: start, end: end})
		}
	}
	return matches
}

func overlaps(matches []Match, start, end int) bool {
	return slices.ContainsFunc(matches, func(m Match) bool {
		return start < m.end && m.start < end
	})
}

var (
	plainIdent  = regexp.MustCompile(`^[A-Za-z_]+$`)
	dottedIdent = regexp.MustCompile(`^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$`)
	constIdent  = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
)

// looksLikeCode: call(), config.TokenStore, TOKEN_ALL_ACCESS.
// JWTs dotted too but start w/ "eyJ".
func looksLikeCode(line string, start, end int) bool {
	s := line[start:end]
	switch {
	case strings.HasPrefix(s, "eyJ"):
		return false
	case strings.HasPrefix(line[end:], "("):
		return true
	}
	return plainIdent.MatchString(s) || dottedIdent.MatchString(s) || constIdent.MatchString(s)
}
