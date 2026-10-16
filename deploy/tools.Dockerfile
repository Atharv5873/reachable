# The seeding image (S10): `make intel && make seed` inside the prod compose
# network, against the prod FalkorDB/Postgres. Built from the repo root with
# deploy/tools.Dockerfile.dockerignore (the root .dockerignore drops data/,
# but seeding needs the committed threat-intel snapshot).
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1

COPY pyproject.toml uv.lock .python-version README.md ./
COPY packages packages
COPY apps/api apps/api
COPY apps/mcp apps/mcp
COPY data/threatintel data/threatintel

RUN uv sync --frozen --no-dev --all-packages

# Exactly what the Makefile's intel + seed targets run (SEED 42, SCALE 1.0):
# load the snapshot into `threatintel`, generate + load the three orgs and
# their v2 scans (FalkorDB + Postgres), then derive the attack layer.
CMD ["sh", "-c", "set -e; uv run --no-sync python -m reachable_intel load; uv run --no-sync python -m reachable_orggen seed --seed ${SEED:-42} --scale 1.0; uv run --no-sync python -m reachable_graph derive"]
