# 🐳 Docker Deployment Guide

Complete guide for deploying the Library Management System using Docker Desktop.

## Prerequisites

1. **Install Docker Desktop**
   - Windows: Download from https://www.docker.com/products/docker-desktop
   - macOS: Download from https://www.docker.com/products/docker-desktop
   - Linux: Follow instructions at https://docs.docker.com/desktop/install/linux-install/

2. **Verify Installation**
   ```bash
   docker --version
   docker-compose --version
   ```

## Deployment Methods

### Method 1: Using Docker Compose (Recommended)

Docker Compose simplifies the deployment process by managing all configurations in a single file.

#### Step 1: Prepare the Project
```bash
# Navigate to project directory
cd library-management-system
```

#### Step 2: Build and Start
```bash
# Build and start in detached mode
docker-compose up -d

# Or build with no cache (if you made changes)
docker-compose up -d --build
```

#### Step 3: Verify Deployment
```bash
# Check if container is running
docker-compose ps

# View logs
docker-compose logs -f library-app
```

#### Step 4: Access the Application
- Open browser: `http://localhost:5000`

#### Step 5: Stop the Application
```bash
# Stop containers
docker-compose stop

# Stop and remove containers
docker-compose down

# Stop and remove containers, volumes, and images
docker-compose down -v --rmi all
```

### Method 2: Using Docker Commands

For more control, you can use Docker commands directly.

#### Step 1: Build the Image
```bash
docker build -t library-management-system:latest .
```

#### Step 2: Create a Volume
```bash
docker volume create library-data
```

#### Step 3: Run the Container
```bash
docker run -d \
  --name library-app \
  -p 5000:5000 \
  -v library-data:/app/data \
  --restart unless-stopped \
  library-management-system:latest
```

#### Step 4: Manage the Container
```bash
# View logs
docker logs -f library-app

# Stop container
docker stop library-app

# Start container
docker start library-app

# Restart container
docker restart library-app

# Remove container
docker rm -f library-app
```

## Docker Desktop GUI

### Using Docker Desktop Interface

1. **Open Docker Desktop**

2. **Images Tab**
   - View built images
   - Delete unused images
   - Pull new images

3. **Containers Tab**
   - See running/stopped containers
   - Start/Stop/Restart containers
   - View logs
   - Open terminal in container
   - Access container settings

4. **Volumes Tab**
   - View persistent data volumes
   - Manage volume storage
   - Backup volumes

### Building from Docker Desktop

1. Click on "Images"
2. Click "Build" button
3. Select Dockerfile location
4. Set image name and tag
5. Click "Build"

### Running Container from Desktop

1. Go to "Images"
2. Find your image
3. Click "Run" button
4. Configure:
   - Container name
   - Port mapping (5000:5000)
   - Volumes
   - Environment variables
5. Click "Run"

## Container Configuration

### Environment Variables

You can set environment variables in docker-compose.yml:

```yaml
environment:
  - FLASK_APP=app.py
  - FLASK_ENV=production
  - SECRET_KEY=your-secret-key-here
```

Or when using docker run:

```bash
docker run -d \
  -e FLASK_APP=app.py \
  -e FLASK_ENV=production \
  -e SECRET_KEY=your-secret-key-here \
  library-management-system:latest
```

### Port Mapping

To use a different port:

```yaml
# docker-compose.yml
ports:
  - "8080:5000"  # Host:Container
```

Or with docker run:

```bash
docker run -p 8080:5000 library-management-system:latest
```

### Volume Mounting

To persist data:

```yaml
volumes:
  - library-data:/app/data
  - ./backups:/app/backups  # For backups
```

## Data Persistence

### Database Backup

#### From Running Container
```bash
# Copy database from container
docker cp library-app:/app/library.db ./backup_$(date +%Y%m%d).db
```

#### Automated Backup Script
```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="./backups"
mkdir -p $BACKUP_DIR
docker cp library-app:/app/library.db "$BACKUP_DIR/library_$(date +%Y%m%d_%H%M%S).db"
echo "Backup completed: $BACKUP_DIR/library_$(date +%Y%m%d_%H%M%S).db"
```

### Restore Database
```bash
# Copy backup to container
docker cp ./backup_20260115.db library-app:/app/library.db

# Restart container
docker restart library-app
```

## Monitoring

### View Real-time Logs
```bash
# Docker Compose
docker-compose logs -f

# Docker Command
docker logs -f library-app
```

### View Container Stats
```bash
docker stats library-app
```

### Execute Commands in Container
```bash
# Interactive shell
docker exec -it library-app /bin/bash

# Run single command
docker exec library-app ls -la /app
```

## Networking

### Access from Other Devices

1. **Find Host IP Address**
   ```bash
   # Windows
   ipconfig
   
   # macOS/Linux
   ifconfig
   ```

2. **Access Application**
   - From other devices: `http://<host-ip>:5000`

### Custom Network

```bash
# Create network
docker network create library-network

# Run with network
docker run -d --network library-network --name library-app library-management-system:latest
```

## Production Deployment

### Security Hardening

1. **Change Secret Key**
   ```bash
   docker run -d \
     -e SECRET_KEY=$(openssl rand -hex 32) \
     library-management-system:latest
   ```

2. **Run as Non-Root User**
   
   Add to Dockerfile:
   ```dockerfile
   RUN useradd -m -u 1000 appuser
   USER appuser
   ```

3. **Health Checks**
   
   Add to docker-compose.yml:
   ```yaml
   healthcheck:
     test: ["CMD", "curl", "-f", "http://localhost:5000"]
     interval: 30s
     timeout: 10s
     retries: 3
   ```

### Resource Limits

```yaml
services:
  library-app:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
```

## Troubleshooting

### Container Won't Start

1. **Check logs**
   ```bash
   docker-compose logs library-app
   ```

2. **Verify image**
   ```bash
   docker images | grep library
   ```

3. **Check port conflicts**
   ```bash
   # Windows
   netstat -ano | findstr :5000
   
   # macOS/Linux
   lsof -i :5000
   ```

### Database Issues

1. **Reset database**
   ```bash
   docker-compose down -v
   docker-compose up -d
   ```

2. **Access database directly**
   ```bash
   docker exec -it library-app sqlite3 /app/library.db
   ```

### Permission Issues

```bash
# Fix volume permissions
docker exec -it library-app chown -R appuser:appuser /app/data
```

## Updating the Application

### Pull Latest Code
```bash
# Stop current container
docker-compose down

# Rebuild with latest changes
docker-compose up -d --build
```

### Rolling Updates
```bash
# Build new version
docker build -t library-management-system:v2 .

# Stop old container
docker stop library-app

# Run new version
docker run -d --name library-app-v2 \
  -p 5000:5000 \
  -v library-data:/app/data \
  library-management-system:v2
```

## Multi-Container Setup

For advanced deployments with separate database:

```yaml
version: '3.8'

services:
  library-app:
    build: .
    ports:
      - "5000:5000"
    depends_on:
      - db
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/library
    
  db:
    image: postgres:14
    volumes:
      - db-data:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=library

volumes:
  db-data:
```

## Best Practices

1. **Always use volumes** for data persistence
2. **Tag your images** with version numbers
3. **Use .dockerignore** to reduce image size
4. **Implement health checks** for reliability
5. **Set resource limits** to prevent resource exhaustion
6. **Regular backups** of data volumes
7. **Monitor logs** for errors
8. **Keep Docker updated** to latest stable version

## Cleanup

### Remove Unused Resources
```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Clean everything
docker system prune -a --volumes
```

### Complete Cleanup
```bash
# Stop and remove everything for this project
docker-compose down -v --rmi all
```

## Quick Reference

### Common Commands
```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# Rebuild
docker-compose up -d --build

# View logs
docker-compose logs -f

# Check status
docker-compose ps

# Restart
docker-compose restart

# Execute command
docker-compose exec library-app /bin/bash
```

---

**Need Help?** Check Docker Desktop documentation at https://docs.docker.com/desktop/
