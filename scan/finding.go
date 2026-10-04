package scan

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// Finding: Commit empty for dir scans.
type Finding struct {
	RuleID      string `json:"rule"`
	Description string `json:"description"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Commit      string `json:"commit,omitempty"`
	Redacted    string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
}

func newFinding(m Match, file string, line int, commit string) Finding {
	sum := sha256.Sum256([]byte(commit + "\x00" + file + "\x00" + m.Rule.ID + "\x00" + m.Secret))
	return Finding{
		RuleID:      m.Rule.ID,
		Description: m.Rule.Description,
		File:        file,
		Line:        line,
		Column:      m.Column,
		Commit:      commit,
		Redacted:    Redact(m.Secret),
		Fingerprint: hex.EncodeToString(sum[:8]),
	}
}

// Redact keeps 1st 4 chars if long.
func Redact(secret string) string {
	if len(secret) < 12 {
		return strings.Repeat("*", 8)
	}
	return secret[:4] + strings.Repeat("*", 8)
}

// Ignore: fingerprints to skip.
type Ignore map[string]bool

// LoadIgnore: 1 fp/line, # comments ok, missing file = empty.
func LoadIgnore(path string) (Ignore, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Ignore{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ig := Ignore{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line, _, _ := strings.Cut(s.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			ig[line] = true
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ig, nil
}

func (ig Ignore) Filter(findings []Finding) []Finding {
	kept := findings[:0]
	for _, f := range findings {
		if !ig[f.Fingerprint] {
			kept = append(kept, f)
		}
	}
	return kept
}
