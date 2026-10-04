package scan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	if got := Redact(fakeGitHub); got != "ghp_********" {
		t.Errorf("Redact = %q", got)
	}
	if got := Redact("short"); got != "********" {
		t.Errorf("Redact(short) = %q", got)
	}
}

func TestFingerprint(t *testing.T) {
	m := NewDetector().Find("AWS=" + fakeAWS)[0]
	a := newFinding(m, "a.env", 3, "c1")
	moved := newFinding(m, "a.env", 40, "c1")
	other := newFinding(m, "a.env", 3, "c2")
	if a.Fingerprint != moved.Fingerprint {
		t.Error("fp changed on line move")
	}
	if a.Fingerprint == other.Fingerprint {
		t.Error("same fp for diff commits")
	}
	if strings.Contains(a.Fingerprint, fakeAWS) || len(a.Fingerprint) != 16 {
		t.Errorf("fingerprint = %q", a.Fingerprint)
	}
}

func TestIgnore(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".leakscanignore")
	content := "# test fixtures\nabc123  # fake key in testdata\n\n  def456\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ig, err := LoadIgnore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := ig.Filter([]Finding{{Fingerprint: "abc123"}, {Fingerprint: "zzz999"}, {Fingerprint: "def456"}})
	if len(got) != 1 || got[0].Fingerprint != "zzz999" {
		t.Errorf("Filter = %+v", got)
	}

	missing, err := LoadIgnore(filepath.Join(t.TempDir(), "nope"))
	if err != nil || len(missing) != 0 {
		t.Errorf("LoadIgnore(missing) = %v, %v", missing, err)
	}
}

func TestWriteSARIF(t *testing.T) {
	m := NewDetector().Find("AWS=" + fakeAWS)[0]
	f := newFinding(m, "config/app.env", 2, "b8aa86081234")

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, []Finding{f}, DefaultRules); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), fakeAWS) {
		t.Fatal("sarif: secret not redacted")
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if log.Version != "2.1.0" || len(run.Tool.Driver.Rules) != len(DefaultRules) || len(run.Results) != 1 {
		t.Fatalf("bad sarif: %s", buf.String())
	}
	r := run.Results[0]
	loc := r.Locations[0].PhysicalLocation
	if r.RuleID != "aws-access-key-id" || loc.ArtifactLocation.URI != "config/app.env" || loc.Region.StartLine != 2 {
		t.Errorf("result = %+v", r)
	}
}

func TestWriteJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(buf.String()); got != "[]" {
		t.Errorf("WriteJSON(nil) = %q, want []", got)
	}
}
