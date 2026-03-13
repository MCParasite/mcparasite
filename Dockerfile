# MCParasite - All-in-one container
#
# Runs the full MCParasite framework: dashboard, CLI, kill chains.
# Includes uv for fast dependency resolution.
#
# Build:
#   docker build -t mcparasite .
#
# Run dashboard:
#   docker run -p 8888:8888 --env-file .env mcparasite dashboard
#
# Run CLI:
#   docker run --env-file .env mcparasite run --channel local --scenario rce_chain

FROM python:3.12-slim AS base

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Deps first (cache layer)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Copy source
COPY mcparasite/ mcparasite/
COPY lab/ lab/
COPY demo/ demo/
COPY tests/ tests/
COPY cli.py ./

# Working dirs
RUN mkdir -p /tmp/mcparasite /data

# Expose dashboard port
EXPOSE 8888

# Entrypoint: supports "dashboard", "run", "benchmark", etc.
ENTRYPOINT ["uv", "run", "python", "cli.py"]
CMD ["--help"]
