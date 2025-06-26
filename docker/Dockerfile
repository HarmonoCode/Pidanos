# Multi-stage Dockerfile for Pidanos
# Stage 1: Builder
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy requirements first for better caching
COPY pidanos-requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --prefix=/install -r pidanos-requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    dnsmasq \
    ca-certificates \
    curl \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Create pidanos user
RUN useradd -r -s /bin/false -U pidanos

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Set working directory
WORKDIR /opt/pidanos

# Copy application files
COPY config/ ./config/
COPY core/ ./core/
COPY src/ ./src/
COPY web/ ./web/
COPY scripts/ ./scripts/
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/supervisord.conf /etc/supervisor/conf.d/pidanos.conf

# Create necessary directories
RUN mkdir -p /var/lib/pidanos \
    /var/log/pidanos \
    /etc/pidanos \
    /opt/pidanos/data \
    && chown -R pidanos:pidanos /var/lib/pidanos \
    /var/log/pidanos \
    /etc/pidanos \
    /opt/pidanos

# Copy default configuration
RUN cp config/pidanos.conf /etc/pidanos/pidanos.conf.default

# Make entrypoint executable
RUN chmod +x /entrypoint.sh

# Expose ports
EXPOSE 53/tcp 53/udp 8080/tcp 8081/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/api/system/health || exit 1

# Environment variables
ENV PYTHONPATH=/opt/pidanos \
    PIDANOS_CONFIG=/etc/pidanos/pidanos.conf \
    PIDANOS_DATA_DIR=/var/lib/pidanos \
    PIDANOS_LOG_DIR=/var/log/pidanos

# Volume mounts
VOLUME ["/etc/pidanos", "/var/lib/pidanos", "/var/log/pidanos"]

# Run as pidanos user
USER pidanos

# Entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]