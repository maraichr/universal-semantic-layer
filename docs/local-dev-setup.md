# Local Development Setup Guide for WSL2

## Prerequisites

1. **Windows 11 or Windows 10 (version 2004+)**
2. **WSL2 enabled with Ubuntu 20.04/22.04**
3. **Docker Desktop with WSL2 backend**
4. **Cursor IDE**

## Initial WSL2 Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install development tools
sudo apt install -y   build-essential   curl   git   wget   unzip   software-properties-common

# Configure Git
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

## Development Environment Setup

### 1. Clone Repository

```bash
cd ~
mkdir -p projects
cd projects
git clone https://github.com/your-org/semantic-layer.git
cd semantic-layer
```

### 2. Install Development Dependencies

```bash
# Run setup script
./scripts/setup-dev-env.sh
```

### 3. Configure Cursor for WSL2

1. Install Cursor on Windows
2. Install WSL extension in Cursor
3. Open project: `cursor .` from WSL2 terminal
4. Configure workspace settings

### 4. Start Local Services

```bash
# Start all services
docker-compose up -d

# Wait for services to be ready
./scripts/wait-for-services.sh

# Initialize Keycloak
./scripts/init-keycloak.sh

# Configure Kong
./scripts/configure-kong.sh
```

### 5. Verify Setup

```bash
# Check service health
curl http://localhost:8000/health
curl http://localhost:8180/health
curl http://localhost:8001/status

# Run tests
./scripts/run-tests.sh
```

## Common Issues and Solutions

### Docker Performance in WSL2

```bash
# Add to ~/.bashrc
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Configure Docker Desktop
# Settings > Resources > WSL Integration > Enable for your distro
```

### Port Conflicts

```bash
# Check for port usage
sudo lsof -i :8080
sudo lsof -i :8000
sudo lsof -i :8180

# Kill process if needed
sudo kill -9 <PID>
```

### Keycloak SSL Issues

```bash
# For local development, disable SSL verification
export NODE_TLS_REJECT_UNAUTHORIZED=0
```

## Development Workflow

1. **Start services**: `docker-compose up -d`
2. **Open Cursor**: `cursor .` in project root
3. **Start backend**: `./mvnw spring-boot:run`
4. **Start frontend**: `cd frontend && npm start`
5. **Access application**: http://localhost:3000

## Useful Commands

```bash
# View logs
docker-compose logs -f keycloak
docker-compose logs -f kong

# Reset everything
docker-compose down -v
./scripts/clean-dev-env.sh

# Update dependencies
./scripts/update-dependencies.sh
```
