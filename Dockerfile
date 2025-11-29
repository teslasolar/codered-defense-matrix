# Multi-stage build for CodeRED Defense Matrix
FROM python:3.10-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir --user -r /tmp/requirements.txt

# Production image
FROM python:3.10-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    net-tools \
    netcat \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Create app directory
WORKDIR /app

# Copy application code
COPY src/ /app/src/
COPY configs/ /app/configs/
COPY deployment/scripts/ /app/scripts/

# Make scripts executable
RUN chmod +x /app/scripts/*.sh

# Environment variables
ENV PYTHONPATH=/app:$PYTHONPATH \
    PATH=/root/.local/bin:$PATH \
    DEFENSE_MODE=patrol \
    DEFENSE_INTENSITY=medium

# Create necessary directories
RUN mkdir -p /var/log/codered /app/data

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.path.append('/app'); from src.swarm.swarm_defender import SwarmDefender; print('OK')"

# Expose ports for API and WebSocket
EXPOSE 3000 6789

# Default command
CMD ["python", "/app/src/swarm/quick_deploy.py", "--mode", "${DEFENSE_MODE}", "--intensity", "${DEFENSE_INTENSITY}"]