package scan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// MaxFileSize: bigger files skipped.
const MaxFileSize = 10 << 20

// 64K default too small for minified js, lockfiles
const maxLineSize = 16 << 20

// ScanDir scans text files under root, skips .git
func (d *Detector) ScanDir(ctx context.Context, root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDir() {
			if e.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		found, err := d.scanEntry(root, path, e)
		findings = append(findings, found...)
		return err
	})
	return findings, err
}

func (d *Detector) scanEntry(root, path string, e fs.DirEntry) ([]Finding, error) {
	if !e.Type().IsRegular() {
		return nil, nil
	}
	info, err := e.Info()
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxFileSize {
		return nil, nil
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	return d.scanFile(path, filepath.ToSlash(rel))
}

func (d *Detector) scanFile(path, name string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	if head, _ := br.Peek(8000); bytes.IndexByte(head, 0) >= 0 {
		return nil, nil
	}
	return d.scanLines(br, name)
}

func (d *Detector) scanLines(r io.Reader, name string) ([]Finding, error) {
	var findings []Finding
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64<<10), maxLineSize)
	for n := 1; s.Scan(); n++ {
		for _, m := range d.Find(s.Text()) {
			findings = append(findings, newFinding(m, name, n, ""))
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", name, err)
	}
	return findings, nil
}
