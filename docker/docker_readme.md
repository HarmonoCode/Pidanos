# Pidanos Docker Deployment

This directory contains Docker configurations for running Pidanos in containers.

## Quick Start

### Using Docker Compose (Recommended)

1. **Build and start all services:**
   ```bash
   docker-compose up -d
   ```

2. **View logs:**
   ```bash
   docker-compose logs -f pidanos
   ```

3. **Stop services:**
   ```bash
   docker-compose down
   ```

### Using Docker directly

1. **Build the image:**
   ```bash
   docker build -t pidanos:latest -f docker/Dockerfile .
   ```

2. **Run the container:**
   ```bash
   docker run -d \
     --name pidanos \
     -p 53:53/tcp -p 53:53/udp \
     -p 8080:8080 \
     -p 8081:8081 \
     -v $(pwd)/config:/etc/pidanos:ro \
     -v pidanos_data:/var/lib/pidanos \
     -v pidanos_logs:/var/log/pidanos \
     --cap-add NET_ADMIN \
     --cap-add NET_BIND_SERVICE \
     pidanos:latest
   ```

## Configuration

### Environment Variables

- `PIDANOS_LOG_LEVEL` - Log level (DEBUG, INFO, WARNING, ERROR)
- `PIDANOS_DNS_PORT` - DNS server port (default: 53)
- `PIDANOS_WEB_PORT` - Web interface port (default: 8080)
- `PIDANOS_API_PORT` - API server port (default: 8081)
- `PIDANOS_UPSTREAM_DNS` - Comma-separated upstream DNS servers
- `DATABASE_TYPE` - Database type (sqlite, postgresql)
- `UPDATE_BLOCKLISTS_ON_START` - Update blocklists on container start (true/false)

### Volumes

- `/etc/pidanos` - Configuration files
- `/var/lib/pidanos` - Persistent data (database, blocklists)
- `/var/log/pidanos` - Log files

### Network Modes

#### Bridge Mode (Default)
Best for development and when running alongside other services:
```yaml
network_mode: bridge
ports:
  - "53:53/tcp"
  - "53:53/udp"
  - "8080:8080"
  - "8081:8081"
```

#### Host Mode
Best for production when Pidanos needs direct network access:
```yaml
network_mode: host
```

## Docker Compose Profiles

The docker-compose.yml includes optional services that can be enabled with profiles:

### PostgreSQL Database
```bash
docker-compose --profile postgres up -d
```

### Redis Cache
```bash
docker-compose --profile redis up -d
```

### Monitoring Stack (Prometheus + Grafana)
```bash
docker-compose --profile monitoring up -d
```

### All Services
```bash
docker-compose --profile postgres --profile redis --profile monitoring up -d
```

## Building Images

### Standard Image (Debian-based)
```bash
docker build -t pidanos:latest -f docker/Dockerfile .
```

### Alpine Image (Lightweight)
```bash
docker build -t pidanos:alpine -f docker/Dockerfile.alpine .
```

## Container Commands

The container supports different run modes:

- **Default**: Runs all services with supervisord
- **DNS only**: `docker run ... pidanos:latest dns`
- **Web only**: `docker run ... pidanos:latest web`
- **API only**: `docker run ... pidanos:latest api`
- **CLI mode**: `docker run ... pidanos:latest cli [commands]`
- **Shell**: `docker run -it ... pidanos:latest bash`

## Health Checks

The container includes health checks that verify:
- DNS server is responding
- API server is accessible
- Database connection is working

Check health status:
```bash
docker inspect --format='{{.State.Health.Status}}' pidanos
```

## Troubleshooting

### Permission Issues
If you encounter permission errors, ensure the pidanos user has proper permissions:
```bash
docker exec pidanos chown -R pidanos:pidanos /var/lib/pidanos /var/log/pidanos
```

### DNS Resolution Issues
1. Check if port 53 is already in use:
   ```bash
   sudo netstat -tulpn | grep :53
   ```

2. Stop systemd-resolved if running:
   ```bash
   sudo systemctl stop systemd-resolved
   ```

### View Container Logs
```bash
# All logs
docker logs pidanos

# Specific service logs
docker exec pidanos tail -f /var/log/pidanos/dns.log
docker exec pidanos tail -f /var/log/pidanos/api.log
docker exec pidanos tail -f /var/log/pidanos/web.log
```

### Access Container Shell
```bash
docker exec -it pidanos bash
```

## Production Deployment

For production deployments:

1. Use the Alpine image for smaller size
2. Configure resource limits appropriately
3. Use external PostgreSQL instead of SQLite
4. Enable Redis for better caching performance
5. Set up proper backup procedures for volumes
6. Configure monitoring with Prometheus/Grafana
7. Use Docker secrets for sensitive configuration