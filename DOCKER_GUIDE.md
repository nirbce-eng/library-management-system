# Docker Deployment Guide

Complete guide for deploying the Library Management System using Docker Desktop.

## Prerequisites

1. **Install Docker Desktop**
   - Windows: https://www.docker.com/products/docker-desktop
   - macOS: https://www.docker.com/products/docker-desktop
   - Linux: https://docs.docker.com/desktop/install/linux-install/

2. **Verify Installation**
   ```bash
   docker --version
   docker compose version
   ```

## Quick Start

```bash
# Start the application
docker compose up -d

# Access at http://localhost:3000
# Login: admin / admin123

# View logs
docker compose logs -f

# Stop
docker compose down
```

## Deployment Methods

### Method 1: Docker Compose (Recommended)

#### Start Application
```bash
cd library-management-system

# Build and start
docker compose up -d

# Or rebuild with changes
docker compose up -d --build
```

#### Verify Deployment
```bash
# Check container status
docker compose ps

# View logs
docker compose logs -f library-app
```

#### Stop Application
```bash
# Stop containers
docker compose stop

# Stop and remove containers
docker compose down

# Stop, remove containers, volumes, and images
docker compose down -v --rmi all
```

### Method 2: Docker Commands

```bash
# Build image
docker build -t library-management-system:latest .

# Create volumes
docker volume create library-data
docker volume create library-logs

# Run container
docker run -d \
  --name library-app \
  -p 3000:5000 \
  -v library-data:/app/data \
  -v library-logs:/app/logs \
  --restart unless-stopped \
  library-management-system:latest

# View logs
docker logs -f library-app

# Stop/Start/Restart
docker stop library-app
docker start library-app
docker restart library-app

# Remove
docker rm -f library-app
```

## Configuration

### docker-compose.yml

```yaml
services:
  library-app:
    build: .
    container_name: library-management-system
    ports:
      - "3000:5000"     # Change 3000 to desired port
    volumes:
      - library-data:/app/data
      - library-logs:/app/logs
    environment:
      - FLASK_APP=app.py
      - FLASK_ENV=production
    restart: unless-stopped

volumes:
  library-data:
    driver: local
  library-logs:
    driver: local
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| FLASK_APP | app.py | Flask application file |
| FLASK_ENV | production | Environment mode |
| PYTHONUNBUFFERED | 1 | Python output buffering |

### Port Configuration

Change the host port by modifying docker-compose.yml:
```yaml
ports:
  - "8080:5000"  # Access at http://localhost:8080
```

## Data Persistence

### Volumes

| Volume | Purpose | Container Path |
|--------|---------|----------------|
| library-data | Database storage | /app/data |
| library-logs | Log files | /app/logs |

### Backup Database

```bash
# Copy from container
docker cp library-management-system:/app/library.db ./backup_$(date +%Y%m%d).db

# Automated backup script
#!/bin/bash
BACKUP_DIR="./backups"
mkdir -p $BACKUP_DIR
docker cp library-management-system:/app/library.db \
  "$BACKUP_DIR/library_$(date +%Y%m%d_%H%M%S).db"
```

### Restore Database

```bash
# Copy backup to container
docker cp ./backup.db library-management-system:/app/library.db

# Restart container
docker restart library-management-system
```

### Backup Logs

```bash
# Copy logs from container
docker cp library-management-system:/app/logs ./logs_backup
```

## Monitoring

### View Logs

```bash
# All logs
docker compose logs -f

# Application logs only
docker compose logs -f library-app

# Last 100 lines
docker compose logs --tail 100 library-app

# View specific log file
docker exec library-management-system cat /app/logs/app.log
docker exec library-management-system cat /app/logs/audit.log
docker exec library-management-system cat /app/logs/error.log
```

### Container Stats

```bash
docker stats library-management-system
```

### Execute Commands

```bash
# Interactive shell
docker exec -it library-management-system /bin/bash

# Run single command
docker exec library-management-system ls -la /app/logs

# Access SQLite database
docker exec -it library-management-system sqlite3 /app/library.db
```

## Networking

### Access from Other Devices

1. Find your host IP:
   ```bash
   # Windows
   ipconfig

   # macOS/Linux
   ifconfig
   ```

2. Access from other devices: `http://<host-ip>:3000`

### Firewall Configuration (Windows)

```powershell
# Allow port 3000
netsh advfirewall firewall add rule name="LibraryOS" dir=in action=allow protocol=tcp localport=3000
```

## Production Deployment

### Security Hardening

1. **Change Secret Key**

   Edit app.py or use environment variable:
   ```yaml
   environment:
     - SECRET_KEY=your-secure-random-key-here
   ```

2. **Disable Debug Mode**

   Already disabled in production (FLASK_ENV=production)

3. **Health Checks**

   Add to docker-compose.yml:
   ```yaml
   healthcheck:
     test: ["CMD", "curl", "-f", "http://localhost:5000/login"]
     interval: 30s
     timeout: 10s
     retries: 3
     start_period: 10s
   ```

### Resource Limits

```yaml
services:
  library-app:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 128M
```

### Restart Policies

| Policy | Description |
|--------|-------------|
| no | Never restart |
| always | Always restart |
| on-failure | Restart on error |
| unless-stopped | Restart unless manually stopped |

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker compose logs library-app

# Check if port is in use
netstat -ano | findstr :3000

# Rebuild container
docker compose down
docker compose up -d --build
```

### Database Issues

```bash
# Reset database (WARNING: deletes all data)
docker compose down -v
docker compose up -d

# Check database file
docker exec library-management-system ls -la /app/library.db
```

### Permission Issues

```bash
# Check file permissions
docker exec library-management-system ls -la /app/

# Fix permissions (if needed)
docker exec library-management-system chmod 644 /app/library.db
```

### Out of Memory

```bash
# Check container memory usage
docker stats library-management-system

# Increase memory limit in docker-compose.yml
deploy:
  resources:
    limits:
      memory: 1G
```

### Logs Not Writing

```bash
# Check logs directory
docker exec library-management-system ls -la /app/logs/

# Check disk space
docker system df
```

## Updating Application

### Standard Update

```bash
# Pull latest code (if using git)
git pull

# Rebuild and restart
docker compose down
docker compose up -d --build
```

### Zero-Downtime Update

```bash
# Build new image
docker compose build

# Recreate container
docker compose up -d --force-recreate
```

## Cleanup

### Remove Unused Resources

```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove unused volumes (WARNING: deletes data)
docker volume prune

# Clean everything
docker system prune -a --volumes
```

### Complete Project Cleanup

```bash
docker compose down -v --rmi all
```

## Quick Reference

| Command | Description |
|---------|-------------|
| `docker compose up -d` | Start application |
| `docker compose down` | Stop application |
| `docker compose up -d --build` | Rebuild and start |
| `docker compose logs -f` | View logs |
| `docker compose ps` | Check status |
| `docker compose restart` | Restart containers |
| `docker compose exec library-app bash` | Shell access |

## Log Files in Container

| File | Path | Description |
|------|------|-------------|
| app.log | /app/logs/app.log | General logs |
| error.log | /app/logs/error.log | Errors only |
| audit.log | /app/logs/audit.log | Security audit |

---

**Need Help?** Check Docker documentation at https://docs.docker.com/
