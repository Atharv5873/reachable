#!/usr/bin/env sh
# The production stack's verbs (S10). Run on the VPS from deploy/:
#   ./prod.sh up         build + start, wait until every healthcheck is green
#   ./prod.sh seed       make intel && make seed, inside the compose network
#   ./prod.sh populate   record the demo runs (needs GEMINI_API_KEY; ~$0.05)
#   ./prod.sh smoke      the HTTPS smoke test against $API_DOMAIN
#   ./prod.sh ps | logs [svc] | down | restart
set -eu
cd "$(dirname "$0")"
[ -f .env.prod ] || { echo "deploy/.env.prod is missing (cp .env.prod.example .env.prod)"; exit 1; }
dc() { docker compose -f docker-compose.prod.yml --env-file .env.prod "$@"; }
# Values for the helper scripts (no export of the whole file into the shell).
val() { sed -n "s/^$1=//p" .env.prod | tail -1; }

cmd="${1:-ps}"
[ $# -gt 0 ] && shift
case "$cmd" in
  up) dc up -d --build --wait ;;
  down) dc down ;; # volumes are kept: graphs, demo runs and certificates survive
  restart) dc down && dc up -d --wait ;;
  ps) dc ps ;;
  logs) dc logs -f --tail=100 "$@" ;;
  seed) dc --profile tools run --rm --build tools ;;
  populate) REACHABLE_API_KEY="$(val REACHABLE_API_KEY)" python3 populate_demo.py --url "https://$(val API_DOMAIN)" "$@" ;;
  smoke) REACHABLE_API_KEY="$(val REACHABLE_API_KEY)" python3 smoke.py --url "https://$(val API_DOMAIN)" "$@" ;;
  *) echo "unknown command: $cmd"; exit 2 ;;
esac
