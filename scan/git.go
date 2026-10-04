package scan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// NUL never in text diffs, no clash w/ content
const commitMarker = "\x00commit "

// ScanGit scans added lines, all commits, all refs.
func (d *Detector) ScanGit(ctx context.Context, repo string) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repo,
		"-c", "core.quotePath=false",
		"log", "-p", "-U0", "--all", "--no-color", "--no-ext-diff", "--no-renames",
		"--format=%x00commit %H")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git start: %w", err)
	}

	findings, parseErr := d.parseLog(out)
	if parseErr != nil {
		// drain, else git blocks on full pipe
		io.Copy(io.Discard, out)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("git log: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return findings, parseErr
}

func (d *Detector) parseLog(r io.Reader) ([]Finding, error) {
	var (
		findings []Finding
		commit   string
		file     string
		line     int
		inHunk   bool
	)
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64<<10), maxLineSize)
	for s.Scan() {
		text := s.Text()
		if hash, ok := strings.CutPrefix(text, commitMarker); ok {
			commit = hash
			file, inHunk = "", false
			continue
		}
		switch {
		case strings.HasPrefix(text, "diff --git "):
			file, inHunk = "", false
		case !inHunk && strings.HasPrefix(text, "+++ "):
			file = parseNewPath(text)
		case strings.HasPrefix(text, "@@ "):
			inHunk = true
			line = parseHunkStart(text)
		case inHunk && file != "" && strings.HasPrefix(text, "+"):
			for _, m := range d.Find(text[1:]) {
				findings = append(findings, newFinding(m, file, line, commit))
			}
			line++
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read git log: %w", err)
	}
	return findings, nil
}

// parseNewPath: "+++ b/path" -> path, "" for deletions.
func parseNewPath(text string) string {
	path, ok := strings.CutPrefix(text, "+++ b/")
	if !ok {
		return ""
	}
	return path
}

// parseHunkStart: "@@ -10,2 +12,3 @@" -> 12.
func parseHunkStart(text string) int {
	_, rest, _ := strings.Cut(text, " +")
	rest, _, _ = strings.Cut(rest, " ")
	rest, _, _ = strings.Cut(rest, ",")
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0
	}
	return n
}
