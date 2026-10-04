package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	dir := t.TempDir()
	secret := "sk_live_" + "51Hx9QkLm2Vn8Rt4Yw6Zp3Bc"
	if err := os.WriteFile(filepath.Join(dir, "billing.go"), []byte(`var k = "`+secret+`"`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	n, err := run(t.Context(), []string{"dir", dir}, &out)
	if err != nil || n != 1 {
		t.Fatalf("run = %d, %v; want 1 finding", n, err)
	}
	if strings.Contains(out.String(), secret) {
		t.Error("secret not redacted")
	}
	fingerprint := strings.Fields(strings.Split(out.String(), "\n")[1])[4]

	ignore := filepath.Join(dir, ".leakscanignore")
	if err := os.WriteFile(ignore, []byte(fingerprint+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if n, err := run(t.Context(), []string{"dir", "-format", "json", dir}, &out); err != nil || n != 0 {
		t.Fatalf("w/ ignore: run = %d, %v; want 0", n, err)
	}
	if strings.TrimSpace(out.String()) != "[]" {
		t.Errorf("json output = %q", out.String())
	}
}

func TestRunErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"scan"},
		{"dir", "-format", "xml", "."},
	} {
		var out bytes.Buffer
		if _, err := run(t.Context(), args, &out); err == nil {
			t.Errorf("run(%q): no err", args)
		}
	}
}
