# Build context is the repo root (see docker-compose.yml), because the API
# depends on the workspace package packages/core.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1

COPY pyproject.toml uv.lock .python-version ./
COPY packages/core packages/core
# Only the pyproject of the other workspace members is needed so uv can resolve
# the workspace; their source is left out of the API image.
COPY packages/intel/pyproject.toml packages/intel/pyproject.toml
COPY packages/orggen/pyproject.toml packages/orggen/pyproject.toml
COPY packages/graph/pyproject.toml packages/graph/pyproject.toml
COPY apps/mcp/pyproject.toml apps/mcp/pyproject.toml
COPY apps/api apps/api

# Install only the API package and its deps (core). Intel/orggen are left out.
RUN uv sync --frozen --no-dev --package reachable-api

EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "reachable_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
