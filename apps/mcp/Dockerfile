# Build context is the repo root (see docker-compose.yml): the MCP server depends
# on the workspace packages core + graph.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1

COPY pyproject.toml uv.lock .python-version ./
COPY packages/core packages/core
COPY packages/graph packages/graph
# Only the pyproject of the other workspace members is needed so uv can resolve
# the workspace; their source is left out of the image.
COPY packages/intel/pyproject.toml packages/intel/pyproject.toml
COPY packages/orggen/pyproject.toml packages/orggen/pyproject.toml
COPY packages/agents/pyproject.toml packages/agents/pyproject.toml
COPY packages/eval/pyproject.toml packages/eval/pyproject.toml
COPY apps/api/pyproject.toml apps/api/pyproject.toml
COPY apps/mcp apps/mcp

RUN uv sync --frozen --no-dev --package reachable-mcp

EXPOSE 8002
CMD ["uv", "run", "--no-sync", "python", "-m", "reachable_mcp.server", "--http", "--host", "0.0.0.0", "--port", "8002"]
