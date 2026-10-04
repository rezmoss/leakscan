#!/usr/bin/env bash
# throwaway repo w/ fake secrets committed then deleted
# keys split so this file has none
set -euo pipefail

dir=${1:?usage: make-demo-repo.sh <dir>}
rm -rf "$dir" && mkdir -p "$dir" && cd "$dir"
git init -q -b main
git config user.name demo
git config user.email demo@example.com

aws="AKIA""Q3XZ7RBN4LKT2WMP"
gh="ghp_""R7mK2xQ9vLp4Tz8NwY3bHc6JdF1sGa5Ue0Vi"
stripe="sk_live_""51Hx9QkLm2Vn8Rt4Yw6Zp3Bc"
awssecret="hT9q/Lm""2+Zx8Vb4Nc7Rk1Wp5Ys3Df6Gj0Qa2Eu8I"

mkdir -p config
cat > config/app.env <<ENV
APP_NAME=shop
AWS_ACCESS_KEY_ID=$aws
AWS_SECRET_ACCESS_KEY=$awssecret
DB_PASSWORD=changeme123
ENV
git add . && git commit -qm "add config"

cat > deploy.sh <<SH
#!/bin/sh
export GITHUB_TOKEN=$gh
curl -H "Authorization: token \$GITHUB_TOKEN" https://api.github.com/user
SH
git add . && git commit -qm "add deploy script"

cat > billing.go <<GO
package billing

var stripeKey = "$stripe"
var apiKey = os.Getenv("API_KEY")
var tokenURL = "https://example.com/oauth/token"
GO
git add . && git commit -qm "add billing"

git rm -q config/app.env deploy.sh
cat > billing.go <<'GO'
package billing

import "os"

var stripeKey = os.Getenv("STRIPE_KEY")
GO
git add . && git commit -qm "remove secrets"
echo "demo repo: $dir"
