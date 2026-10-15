# Build context is the repo root (see docker-compose.yml). Since S5 the API runs
# the agents (runs + SSE), so it needs core, graph, mcp and agents; intel/orggen
# stay out (only their pyproject, so uv can resolve the workspace).
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1

COPY pyproject.toml uv.lock .python-version ./
COPY packages/core packages/core
COPY packages/graph packages/graph
COPY packages/agents packages/agents
COPY apps/mcp apps/mcp
COPY packages/intel/pyproject.toml packages/intel/pyproject.toml
COPY packages/orggen/pyproject.toml packages/orggen/pyproject.toml
COPY packages/eval/pyproject.toml packages/eval/pyproject.toml
COPY apps/api apps/api
# GET /evals serves the eval results (S6 UI); S7 refreshes them.
COPY evals/results evals/results

RUN uv sync --frozen --no-dev --package reachable-api

EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "reachable_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
