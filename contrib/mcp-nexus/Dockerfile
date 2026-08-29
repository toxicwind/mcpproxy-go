FROM python:3.12-slim

LABEL maintainer="Lightcap AI <dev@lightcap.ai>"
LABEL description="MCP Nexus — Remote server management via Model Context Protocol"

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Package metadata + app code
COPY README.md LICENSE pyproject.toml ./
COPY mcp_nexus/ mcp_nexus/
RUN pip install --no-cache-dir .

# Non-root user
RUN useradd -m nexus \
    && mkdir -p /home/nexus/.mcp-nexus \
    && chown -R nexus:nexus /home/nexus
USER nexus

EXPOSE 8766

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -m mcp_nexus health || exit 1

ENTRYPOINT ["python", "-m", "mcp_nexus"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8766"]
