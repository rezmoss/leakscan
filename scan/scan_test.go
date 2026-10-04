package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// split so push protection wont flag
var (
	fakeAWS    = "AKIA" + "Q3XZ7RBN4LKT2WMP"
	fakeGitHub = "ghp_" + "R7mK2xQ9vLp4Tz8NwY3bHc6JdF1sGa5Ue0Vi"
	fakeSlack  = "xoxb" + "-2210391-8812736123-kTz9QwLm4Rv"
	fakeStripe = "sk_live_" + "51Hx9QkLm2Vn8Rt4Yw6Zp3Bc"
	fakePEM    = "-----BEGIN RSA " + "PRIVATE KEY-----"
	fakeAPIKey = "hT9q/Lm" + "2+Zx8Vb4Nc7Rk1Wp5Ys3Df6Gj0Qa2Eu8I"
	fakeJWT    = "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.Xk3vQ9mZpL2rT8wY4nB6cH1jF5sD0aGe"
)

func TestEntropy(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"aaaa", 0},
		{"ab", 1},
		{"abcd", 2},
	}
	for _, tt := range tests {
		if got := Entropy(tt.in); got != tt.want {
			t.Errorf("Entropy(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
	for _, s := range []string{"changeme123", "os.Getenv", "password1234", fakeAPIKey, fakeAWS, fakeGitHub} {
		t.Logf("%-45q %.2f", s, Entropy(s))
	}
}

func TestFind(t *testing.T) {
	tests := []struct {
		line string
		rule string
	}{
		{"AWS_ACCESS_KEY_ID=" + fakeAWS, "aws-access-key-id"},
		{"export GITHUB_TOKEN=" + fakeGitHub, "github-token"},
		{`slack: "` + fakeSlack + `"`, "slack-token"},
		{`var key = "` + fakeStripe + `"`, "stripe-live-key"},
		{fakePEM, "private-key"},
		{"aws_secret_access_key = " + fakeAPIKey, "generic-secret"},
		{`"api_key": "` + fakeAPIKey + `"`, "generic-secret"},
		{"AUTH_TOKEN=" + fakeJWT, "generic-secret"},
	}
	d := NewDetector()
	for _, tt := range tests {
		got := d.Find(tt.line)
		if len(got) != 1 || got[0].Rule.ID != tt.rule {
			t.Errorf("Find(%q) = %v, want one %s match", tt.line, ruleIDs(got), tt.rule)
		}
	}
}

func TestFindIgnoresLowEntropy(t *testing.T) {
	d := NewDetector()
	for _, line := range []string{
		"DB_PASSWORD=changeme123",
		`apiKey := os.Getenv("API_KEY")`,
		"token: ${{ secrets.GITHUB_TOKEN }}",
		`tokenURL = "https://example.com/oauth/token"`,
		"password = xxxxxxxxxxxxxxxx",
		"tokens = docGroup.Tokens",
		"TokenStore: config.TokenStore,",
		`procAdjustTokenGroups = modadvapi32.NewProc("AdjustTokenGroups")`,
		"TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |",
		"tokenToOriginMap: tokenToOriginMap,",
		"clientSecret = hkdfExpandLabel(crypto.SHA256, initialSecret)",
	} {
		if got := d.Find(line); len(got) != 0 {
			t.Errorf("Find(%q) = %v, want none", line, ruleIDs(got))
		}
	}

	d.MinEntropy = 0
	if got := d.Find("DB_PASSWORD=changeme123"); len(got) != 1 {
		t.Errorf("entropy 0: Find = %v, want 1", ruleIDs(got))
	}
}

func ruleIDs(ms []Match) []string {
	var ids []string
	for _, m := range ms {
		ids = append(ids, m.Rule.ID)
	}
	return ids
}

func TestParseLog(t *testing.T) {
	log := strings.Join([]string{
		"\x00commit aaaa1111",
		"",
		"diff --git a/app.env b/app.env",
		"new file mode 100644",
		"--- /dev/null",
		"+++ b/app.env",
		"@@ -0,0 +1,3 @@",
		"+NAME=shop",
		"+++ not a header, just an added line starting with ++",
		"+AWS=" + fakeAWS,
		"diff --git a/old.txt b/old.txt",
		"deleted file mode 100644",
		"--- a/old.txt",
		"+++ /dev/null",
		"@@ -1 +0,0 @@",
		"-AWS=" + fakeAWS,
		"\x00commit bbbb2222",
		"",
		"diff --git a/main.go b/main.go",
		"--- a/main.go",
		"+++ b/main.go",
		"@@ -10,0 +11,1 @@",
		"+var k = \"" + fakeStripe + "\"",
		"@@ -20 +21 @@",
		"-x := 1",
		"+x := \"" + fakeGitHub + "\"",
	}, "\n")

	got, err := NewDetector().parseLog(strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		rule, file, commit string
		line               int
	}{
		{"aws-access-key-id", "app.env", "aaaa1111", 3},
		{"stripe-live-key", "main.go", "bbbb2222", 11},
		{"github-token", "main.go", "bbbb2222", 21},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		f := got[i]
		if f.RuleID != w.rule || f.File != w.file || f.Commit != w.commit || f.Line != w.line {
			t.Errorf("finding %d = %s %s:%d @%s, want %s %s:%d @%s",
				i, f.RuleID, f.File, f.Line, f.Commit, w.rule, w.file, w.line, w.commit)
		}
	}
}

func TestScanGitFindsDeletedSecret(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	git("init", "-q", "-b", "main")
	git("config", "user.name", "test")
	git("config", "user.email", "test@example.com")
	write("config.env", "NAME=shop\nREGION=us-east-1\nAWS_ACCESS_KEY_ID="+fakeAWS+"\n")
	git("add", ".")
	git("commit", "-qm", "add config")
	git("rm", "-q", "config.env")
	write("README.md", "nothing to see\n")
	git("add", ".")
	git("commit", "-qm", "remove config")

	d := NewDetector()
	inTree, err := d.ScanDir(t.Context(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(inTree) != 0 {
		t.Errorf("ScanDir: %d findings in clean tree", len(inTree))
	}

	history, err := d.ScanGit(t.Context(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("ScanGit found %d findings, want 1: %+v", len(history), history)
	}
	if f := history[0]; f.File != "config.env" || f.Line != 3 || len(f.Commit) != 40 {
		t.Errorf("finding = %+v, want config.env:3 w/ full hash", f)
	}
}

func TestScanGitNotARepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	_, err := NewDetector().ScanGit(t.Context(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("err = %v, want 'not a git repository'", err)
	}
}

func TestScanDir(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"app/config.yml":   "db:\n  host: localhost\nstripe: " + fakeStripe + "\n",
		"dist/app.min.js":  strings.Repeat("a", 200_000) + ";var t=\"" + fakeGitHub + "\"\n",
		"image.png":        "\x89PNG\x00\x00" + fakeAWS,
		".git/config.orig": fakeAWS,
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := NewDetector().ScanDir(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	SortFindings(got)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	if got[0].File != "app/config.yml" || got[0].Line != 3 {
		t.Errorf("1st = %s:%d, want app/config.yml:3", got[0].File, got[0].Line)
	}
	if got[1].File != "dist/app.min.js" || got[1].RuleID != "github-token" {
		t.Errorf("2nd = %s %s, want github-token in dist/app.min.js", got[1].RuleID, got[1].File)
	}
}
