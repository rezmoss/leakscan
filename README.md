# leakscan

A small secret scanner written in Go. It finds leaked API keys, tokens and private keys in a directory or in **every commit of a git repository's history**, including secrets that were "deleted" in a later commit.


## Requirements

- Go 1.26 or newer
- `git` on your `PATH` (for `leakscan git`)

No third-party Go dependencies.

## Install, build, test

```bash
go install github.com/rezmoss/leakscan@latest

# or from a clone
go test ./...
go build -o leakscan .
```

## Usage

```bash
leakscan dir [flags] [path]   # scan files on disk, skipping .git (default path ".")
leakscan git [flags] [path]   # scan every line ever added on any branch or tag
```

Try it on a throwaway repo with fake keys that are committed and then removed:

```bash
./demo/make-demo-repo.sh /tmp/leakscan-demo
./leakscan dir /tmp/leakscan-demo   # 0 findings, the files are gone
./leakscan git /tmp/leakscan-demo   # 4 findings, history still has them
```

Secrets are always redacted in output. Each finding has a fingerprint, a hash of the commit, file, rule and secret, so it doesn't change when lines move.

## Flags

| Flag | Default | Description |
|---|---|---|
| `-format` | `text` | `text`, `json` or `sarif` |
| `-entropy` | `3.5` | minimum Shannon entropy (bits per byte) for the `generic-secret` rule |
| `-ignore` | `<path>/.leakscanignore` | file of fingerprints to skip |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no findings |
| 1 | findings |
| 2 | error (bad flags, not a git repository, ...) |

## Ignoring findings

Put fingerprints in `.leakscanignore`, one per line. `#` starts a comment.

```
# test certificates
3e23651ff068e7ea  # testdata/server.key
```

## Rules

| ID | Finds |
|---|---|
| `aws-access-key-id` | `AKIA…` / `ASIA…` access key IDs |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_` tokens |
| `slack-token` | `xoxb-`, `xoxp-` and other Slack tokens |
| `stripe-live-key` | `sk_live_` / `rk_live_` keys |
| `private-key` | `-----BEGIN … PRIVATE KEY-----` lines |
| `generic-secret` | values assigned to `api_key`, `secret`, `token`, `password` names, filtered by entropy and skipped when they look like code |

## GitHub Actions

[`examples/leakscan-workflow.yml`](examples/leakscan-workflow.yml) scans the full history and uploads SARIF to GitHub code scanning. Keep `fetch-depth: 0`, or the checkout only has the last commit.

## If you find a real secret

Revoke and rotate it first. Rewriting history does not help once the key has been pushed: forks, clones and caches still have it.
