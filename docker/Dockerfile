# Dockerfile for Cyber-AutoAgent (Kali Rolling base)
# syntax=docker/dockerfile:1.7

ARG APT_PROXY

FROM cyber-autoagent-tools:latest

LABEL org.opencontainers.image.title="Cyber-AutoAgent"
LABEL org.opencontainers.image.description="Autonomous AI agent for ethical security assessments"
LABEL org.opencontainers.image.version="0.3.1"
LABEL org.opencontainers.image.source="https://github.com/double16/cyber-autoagent"
LABEL org.opencontainers.image.licenses="MIT"

COPY docker/apt_proxy_configure.sh docker/apt_proxy_clean.sh /tmp/
RUN /tmp/apt_proxy_configure.sh

# Set working directory
WORKDIR /app

# Copy dependency descriptors and source
COPY pyproject.toml ./
COPY uv.lock* ./

# Install Python dependencies into a local venv
RUN --mount=type=cache,target=/root/.cache \
    uv sync --no-dev --no-install-project

# Install chromium browser for playwright to use
RUN --mount=type=cache,target=/root/.cache \
    env PLAYWRIGHT_HOST_PLATFORM_OVERRIDE="debian13-$(dpkg --print-architecture | sed 's/amd/x/')" \
    PLAYWRIGHT_BROWSERS_PATH=/home/cyberagent/.cache/ms-playwright \
    uv run --no-project playwright install chromium --with-deps && \
    chown -R cyberagent:cyberagent /home/cyberagent/.cache && \
    CHROME_BIN=$(find /home/cyberagent/.cache/ms-playwright -type f \( -name chrome -o -name chromium \) | head -n 1) && \
    if [ -n "$CHROME_BIN" ]; then mkdir -p /usr/lib/chromium && ln -sf "$CHROME_BIN" /usr/lib/chromium/chromium; fi && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

COPY src/ ./src/

# Install Python dependencies into a local venv
RUN --mount=type=cache,target=/root/.cache \
    uv sync --no-dev

# Install and build React terminal interface (default UI)
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=cache,target=/root/.cache \
    cd /app/src/modules/interfaces/react && \
    npm install && \
    npm run build && \
    chown -R cyberagent:cyberagent /app/src/modules/interfaces/react

RUN /tmp/apt_proxy_clean.sh

# Environment
ENV GOPATH="/home/cyberagent/go"
ENV GOCACHE="/home/cyberagent/go/.cache"
ENV PATH="/app/.venv/bin:/home/cyberagent/go/bin:$PATH"
ENV PLAYWRIGHT_BROWSERS_PATH="/home/cyberagent/.cache/ms-playwright"
ENV PYTHONPATH="/usr/lib/python3/dist-packages:/app/src"

# Persist important directories
VOLUME ["/app/evidence", "/app/logs"]

# Expose port for any web interfaces 
EXPOSE 8080

# Health check (always-healthy placeholder; app exposes no service port by default)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default entrypoint: React terminal (which spawns Python agent as subprocess)
# Falls back to direct Python execution if given --python-direct flag
ENTRYPOINT ["node", "/app/src/modules/interfaces/react/dist/index.js"]
