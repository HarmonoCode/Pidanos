#!/bin/bash
set -e

# Pidanos Docker Entrypoint Script

echo "Starting Pidanos DNS Filter..."

# Function to wait for a service
wait_for_service() {
    local host="$1"
    local port="$2"
    local service="$3"
    local max_attempts=30
    local attempt=1
    
    echo "Waiting for $service at $host:$port..."
    
    while ! nc -z "$host" "$port" >/dev/null 2>&1; do
        if [ $attempt -eq $max_attempts ]; then
            echo "Error: $service did not become available"
            return 1
        fi
        echo "Attempt $attempt/$max_attempts: $service not ready, waiting..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo "$service is available"
    return 0
}

# Create necessary directories if they don't exist
mkdir -p ${PIDANOS_DATA_DIR} ${PIDANOS_LOG_DIR} ${PIDANOS_DATA_DIR}/blocklists ${PIDANOS_DATA_DIR}/cache

# Copy default config if not exists
if [ ! -f "${PIDANOS_CONFIG}" ]; then
    echo "No configuration found, copying default..."
    cp /etc/pidanos/pidanos.conf.default "${PIDANOS_CONFIG}"
fi

# Check if we're using PostgreSQL
if [ "${DATABASE_TYPE}" = "postgresql" ]; then
    wait_for_service "${POSTGRES_HOST:-postgres}" "${POSTGRES_PORT:-5432}" "PostgreSQL"
fi

# Check if we're using Redis
if [ "${CACHE_TYPE}" = "redis" ]; then
    wait_for_service "${REDIS_HOST:-redis}" "${REDIS_PORT:-6379}" "Redis"
fi

# Run database migrations
echo "Running database migrations..."
python -m scripts.migrate_db

# Update blocklists on startup if enabled
if [ "${UPDATE_BLOCKLISTS_ON_START}" = "true" ]; then
    echo "Updating blocklists..."
    python -m scripts.update_blocklists
fi

# Validate configuration
echo "Validating configuration..."
python -m scripts.validate_config "${PIDANOS_CONFIG}"

# Set proper permissions
if [ "$(id -u)" = "0" ]; then
    chown -R pidanos:pidanos ${PIDANOS_DATA_DIR} ${PIDANOS_LOG_DIR}
fi

# Handle different run modes
case "${1}" in
    "dns")
        echo "Starting DNS server only..."
        exec python -m src.dns_server
        ;;
    "web")
        echo "Starting web interface only..."
        exec python -m src.web_server
        ;;
    "api")
        echo "Starting API server only..."
        exec python -m src.api_server
        ;;
    "cli")
        echo "Starting CLI mode..."
        shift
        exec python pidanos-cli.py "$@"
        ;;
    "supervisord")
        echo "Starting all services with supervisord..."
        exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
        ;;
    "bash"|"sh")
        echo "Starting shell..."
        exec /bin/bash
        ;;
    *)
        # Default: run supervisord
        echo "Starting all services..."
        exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
        ;;
esac