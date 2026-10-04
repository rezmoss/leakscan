// Command leakscan finds secrets in dirs & git history.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/rezmoss/leakscan/scan"
)

const usage = `usage: leakscan <dir|git> [flags] [path]

  dir   scan files in a directory (default ".")
  git   scan added lines in all git history (default ".")

flags:
`

// exit: 0 clean, 1 findings, 2 err
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	n, err := run(ctx, os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "leakscan:", err)
		os.Exit(2)
	}
	if n > 0 {
		os.Exit(1)
	}
}

type options struct {
	mode       string
	root       string
	format     string
	ignorePath string
	entropy    float64
}

func parseArgs(args []string) (options, error) {
	fs := flag.NewFlagSet("leakscan", flag.ContinueOnError)
	opts := options{root: "."}
	fs.StringVar(&opts.format, "format", "text", "output format: text, json or sarif")
	fs.StringVar(&opts.ignorePath, "ignore", "", "fingerprint ignore file (default <path>/.leakscanignore)")
	fs.Float64Var(&opts.entropy, "entropy", scan.DefaultMinEntropy, "min entropy for generic secrets")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}

	if len(args) == 0 {
		fs.Usage()
		return opts, errors.New("missing command")
	}
	opts.mode = args[0]
	if opts.mode != "dir" && opts.mode != "git" {
		fs.Usage()
		return opts, fmt.Errorf("unknown command %q", opts.mode)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return opts, err
	}
	if fs.NArg() > 0 {
		opts.root = fs.Arg(0)
	}
	if opts.ignorePath == "" {
		opts.ignorePath = filepath.Join(opts.root, ".leakscanignore")
	}
	return opts, nil
}

// returns # findings
func run(ctx context.Context, args []string, stdout io.Writer) (int, error) {
	opts, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	write, ok := writers[opts.format]
	if !ok {
		return 0, fmt.Errorf("unknown format %q", opts.format)
	}

	d := scan.NewDetector()
	d.MinEntropy = opts.entropy

	var findings []scan.Finding
	switch opts.mode {
	case "git":
		findings, err = d.ScanGit(ctx, opts.root)
	case "dir":
		findings, err = d.ScanDir(ctx, opts.root)
	}
	if err != nil {
		return 0, err
	}

	ignore, err := scan.LoadIgnore(opts.ignorePath)
	if err != nil {
		return 0, err
	}
	findings = ignore.Filter(findings)
	scan.SortFindings(findings)

	return len(findings), write(stdout, findings, d.Rules)
}

var writers = map[string]func(io.Writer, []scan.Finding, []scan.Rule) error{
	"text":  func(w io.Writer, f []scan.Finding, _ []scan.Rule) error { return scan.WriteText(w, f) },
	"json":  func(w io.Writer, f []scan.Finding, _ []scan.Rule) error { return scan.WriteJSON(w, f) },
	"sarif": scan.WriteSARIF,
}
