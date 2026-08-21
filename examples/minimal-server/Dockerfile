ARG PYTHON_VERSION=3.13-slim
FROM python:${PYTHON_VERSION}

# System deps: keep minimal. Add gcc/python3-dev only if a dependency needs to
# compile. No `git` unless something is installed from a VCS URL.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1
ENV PORT=5000

RUN useradd -m -u 10001 appuser
WORKDIR /app

# Dependencies first, so app-code edits do not invalidate this layer.
#
# NOTE: no --prerelease=allow. Allowing prereleases here once resolved fastmcp to
# a 4.0 beta, which pulled mcp 2.x and removed a module the app imported; the
# image built green and died at import. Betas do not belong in a production image.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir uv \
 && uv pip install --system --no-cache -r /app/requirements.txt

COPY pyproject.toml /app/
COPY my_mcp/ /app/my_mcp
RUN uv pip install --system --no-cache --no-deps /app

USER appuser
EXPOSE 5000
CMD ["python", "-m", "my_mcp"]
