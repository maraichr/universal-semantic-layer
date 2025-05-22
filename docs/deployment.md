# Deployment Guide

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Pre-Deployment Checklist](#pre-deployment-checklist)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Cloud Platform Deployment](#cloud-platform-deployment)
7. [On-Premises Deployment](#on-premises-deployment)
8. [Configuration Management](#configuration-management)
9. [Security Setup](#security-setup)
10. [Monitoring and Logging](#monitoring-and-logging)
11. [Backup and Recovery](#backup-and-recovery)
12. [Performance Tuning](#performance-tuning)
13. [Troubleshooting](#troubleshooting)

---

## Overview

This guide provides comprehensive instructions for deploying the Universal Semantic Layer Application across different environments and platforms. The application is designed to be cloud-native and supports multiple deployment strategies.

### Deployment Architecture Options

- **Single Server**: Development and small teams
- **Multi-Server**: Production with load balancing
- **Container-Based**: Docker and Kubernetes deployments
- **Cloud-Native**: AWS, Azure, GCP managed services
- **Hybrid**: On-premises with cloud integration

---

## System Requirements

### Minimum Requirements

#### Hardware
- **CPU**: 4 cores (2.4 GHz or higher)
- **RAM**: 8 GB
- **Storage**: 100 GB SSD
- **Network**: 1 Gbps connection

#### Software
- **Operating System**: 
  - Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
  - Windows Server 2019+
  - macOS 11+ (development only)
- **Java**: OpenJDK 17 or Oracle Java 17+
- **Node.js**: 18.x or 20.x
- **Database**: PostgreSQL 13+
- **Cache**: Redis 6+

### Recommended Production Requirements

#### Hardware
- **CPU**: 8+ cores (3.0 GHz or higher)
- **RAM**: 32 GB+
- **Storage**: 500 GB+ NVMe SSD
- **Network**: 10 Gbps connection

#### Infrastructure
- **Load Balancer**: Nginx, HAProxy, or cloud ALB
- **Database**: PostgreSQL cluster with read replicas
- **Cache**: Redis cluster with persistence
- **Monitoring**: Prometheus + Grafana
- **Log Management**: ELK Stack or cloud logging

### Scaling Guidelines

| User Count | CPU Cores | RAM | Database | Cache |
|------------|-----------|-----|----------|-------|
| 1-50 | 4 | 8 GB | Single PostgreSQL | Single Redis |
| 50-200 | 8 | 16 GB | PostgreSQL + 1 replica | Redis cluster |
| 200-1000 | 16 | 32 GB | PostgreSQL cluster | Redis cluster |
| 1000+ | 32+ | 64+ GB | PostgreSQL cluster + sharding | Redis cluster |

---

## Pre-Deployment Checklist

### Infrastructure Preparation

- [ ] **Network Configuration**
  - [ ] Firewall rules configured
  - [ ] Load balancer set up (if applicable)
  - [ ] SSL certificates obtained and configured
  - [ ] DNS records configured

- [ ] **Database Setup**
  - [ ] PostgreSQL instance provisioned
  - [ ] Database and user created
  - [ ] Connection pool configured
  - [ ] Backup strategy implemented

- [ ] **Cache Setup**
  - [ ] Redis instance provisioned
  - [ ] Memory allocation configured
  - [ ] Persistence settings configured
  - [ ] Security settings applied

- [ ] **Security Preparation**
  - [ ] SSL/TLS certificates
  - [ ] API keys and secrets generated
  - [ ] Authentication provider configured
  - [ ] Security scanning completed

### Environment Variables

Create environment-specific configuration files:

```bash
# Database Configuration
DATABASE_URL=postgresql://username:password@host:5432/semantic_layer
DATABASE_POOL_SIZE=20
DATABASE_MAX_CONNECTIONS=100

# Redis Configuration
REDIS_URL=redis://host:6379
REDIS_PASSWORD=redis_password
REDIS_MAX_CONNECTIONS=50

# Application Configuration
APP_ENV=production
APP_PORT=8080
APP_HOST=0.0.0.0
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRATION=86400

# External Services
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=smtp_user
SMTP_PASSWORD=smtp_password

# Monitoring
PROMETHEUS_ENABLED=true
METRICS_PORT=9090
LOG_LEVEL=info
```

---

## Docker Deployment

### Single Container Setup

#### 1. Pull the Official Image

```bash
docker pull universalsemantic/semantic-layer:latest
```

#### 2. Create Docker Compose File

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  semantic-layer:
    image: universalsemantic/semantic-layer:latest
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/semantic_layer
      - REDIS_URL=redis://cache:6379
      - JWT_SECRET=your-secret-key
    depends_on:
      - db
      - cache
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=semantic_layer
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"

  cache:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass redis_password
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - semantic-layer

volumes:
  postgres_data:
  redis_data:
```

#### 3. Create Nginx Configuration

Create `nginx.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream semantic_layer {
        server semantic-layer:8080;
    }

    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        location / {
            proxy_pass http://semantic_layer;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /api/v1/queries/stream {
            proxy_pass http://semantic_layer;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
```

#### 4. Deploy the Stack

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f semantic-layer

# Scale the application
docker-compose up -d --scale semantic-layer=3
```

### Production Docker Setup

#### Multi-Stage Dockerfile

```dockerfile
# Build stage
FROM maven:3.9-openjdk-17 AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Frontend build
FROM node:18-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci --only=production
COPY frontend/ ./
RUN npm run build

# Runtime stage
FROM openjdk:17-jre-slim
WORKDIR /app

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Copy application
COPY --from=builder /app/target/semantic-layer.jar ./
COPY --from=frontend-builder /app/dist ./static/

# Create non-root user
RUN groupadd -r semantic && useradd -r -g semantic semantic
RUN chown -R semantic:semantic /app
USER semantic

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["java", "-jar", "semantic-layer.jar"]
```

---

## Kubernetes Deployment

### Namespace and ConfigMap

#### 1. Create Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: semantic-layer
  labels:
    name: semantic-layer
```

#### 2. Create ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: semantic-layer-config
  namespace: semantic-layer
data:
  application.yml: |
    server:
      port: 8080
    spring:
      datasource:
        url: jdbc:postgresql://postgres-service:5432/semantic_layer
        driver-class-name: org.postgresql.Driver
      redis:
        host: redis-service
        port: 6379
    management:
      endpoints:
        web:
          exposure:
            include: health,info,metrics
      endpoint:
        health:
          show-details: always
```

### Secret Management

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: semantic-layer-secrets
  namespace: semantic-layer
type: Opaque
data:
  database-username: cG9zdGdyZXM=  # base64 encoded
  database-password: cGFzc3dvcmQ=  # base64 encoded
  redis-password: cmVkaXNfcGFzcw==    # base64 encoded
  jwt-secret: eW91cl9qd3Rfc2VjcmV0  # base64 encoded
```

### Deployment Manifests

#### 1. PostgreSQL Deployment

```yaml
# postgres-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: semantic-layer
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: semantic_layer
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: semantic-layer-secrets
              key: database-username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: semantic-layer-secrets
              key: database-password
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1"
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc

---
apiVersion: v1
kind: Service
metadata:
  name: postgres-service
  namespace: semantic-layer
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: semantic-layer
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
```

#### 2. Redis Deployment

```yaml
# redis-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: semantic-layer
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        command:
        - redis-server
        - --appendonly
        - "yes"
        - --requirepass
        - $(REDIS_PASSWORD)
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: semantic-layer-secrets
              key: redis-password
        volumeMounts:
        - name: redis-storage
          mountPath: /data
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: redis-storage
        persistentVolumeClaim:
          claimName: redis-pvc

---
apiVersion: v1
kind: Service
metadata:
  name: redis-service
  namespace: semantic-layer
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
  type: ClusterIP

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-pvc
  namespace: semantic-layer
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

#### 3. Application Deployment

```yaml
# app-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: semantic-layer
  namespace: semantic-layer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: semantic-layer
  template:
    metadata:
      labels:
        app: semantic-layer
    spec:
      containers:
      - name: semantic-layer
        image: universalsemantic/semantic-layer:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          value: "postgresql://$(DATABASE_USERNAME):$(DATABASE_PASSWORD)@postgres-service:5432/semantic_layer"
        - name: DATABASE_USERNAME
          valueFrom:
            secretKeyRef:
              name: semantic-layer-secrets
              key: database-username
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: semantic-layer-secrets
              key: database-password
        - name: REDIS_URL
          value: "redis://:$(REDIS_PASSWORD)@redis-service:6379"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: semantic-layer-secrets
              key: redis-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: semantic-layer-secrets
              key: jwt-secret
        volumeMounts:
        - name: config-volume
          mountPath: /app/config
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
      volumes:
      - name: config-volume
        configMap:
          name: semantic-layer-config

---
apiVersion: v1
kind: Service
metadata:
  name: semantic-layer-service
  namespace: semantic-layer
spec:
  selector:
    app: semantic-layer
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

#### 4. Ingress Configuration

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: semantic-layer-ingress
  namespace: semantic-layer
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
spec:
  tls:
  - hosts:
    - semantic.yourdomain.com
    secretName: semantic-layer-tls
  rules:
  - host: semantic.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: semantic-layer-service
            port:
              number: 80
```

### Horizontal Pod Autoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: semantic-layer-hpa
  namespace: semantic-layer
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: semantic-layer
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Deploy to Kubernetes

```bash
# Apply all manifests
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml
kubectl apply -f configmap.yaml
kubectl apply -f postgres-deployment.yaml
kubectl apply -f redis-deployment.yaml
kubectl apply -f app-deployment.yaml
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml

# Check deployment status
kubectl get pods -n semantic-layer
kubectl get services -n semantic-layer
kubectl get ingress -n semantic-layer

# View logs
kubectl logs -f deployment/semantic-layer -n semantic-layer

# Scale deployment
kubectl scale deployment semantic-layer --replicas=5 -n semantic-layer
```

---

## Cloud Platform Deployment

### AWS Deployment

#### EKS with Terraform

Create `main.tf`:

```hcl
provider "aws" {
  region = var.aws_region
}

# VPC and Networking
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "semantic-layer-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = true
  
  tags = {
    Environment = var.environment
    Project     = "semantic-layer"
  }
}

# EKS Cluster
module "eks" {
  source = "terraform-aws-modules/eks/aws"
  
  cluster_name    = "semantic-layer-cluster"
  cluster_version = "1.28"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  node_groups = {
    main = {
      desired_capacity = 3
      max_capacity     = 10
      min_capacity     = 3
      
      instance_types = ["t3.large"]
      
      k8s_labels = {
        Environment = var.environment
        Application = "semantic-layer"
      }
    }
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "postgres" {
  identifier = "semantic-layer-db"
  
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_encrypted     = true
  
  db_name  = "semantic_layer"
  username = var.db_username
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "semantic-layer-final-snapshot"
  
  tags = {
    Environment = var.environment
    Project     = "semantic-layer"
  }
}

# ElastiCache Redis
resource "aws_elasticache_subnet_group" "main" {
  name       = "semantic-layer-cache-subnet"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "semantic-layer-redis"
  description                = "Redis cluster for semantic layer"
  
  node_type            = "cache.t3.micro"
  port                 = 6379
  parameter_group_name = "default.redis7"
  
  num_cache_clusters = 2
  
  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                = var.redis_password
  
  tags = {
    Environment = var.environment
    Project     = "semantic-layer"
  }
}
```

#### Deploy with Terraform

```bash
# Initialize Terraform
terraform init

# Plan deployment
terraform plan -var-file="production.tfvars"

# Apply configuration
terraform apply -var-file="production.tfvars"

# Get EKS config
aws eks update-kubeconfig --region us-west-2 --name semantic-layer-cluster

# Deploy application to EKS
kubectl apply -f k8s/
```

### Azure Deployment

#### AKS with ARM Templates

Create `azuredeploy.json`:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "clusterName": {
      "type": "string",
      "defaultValue": "semantic-layer-aks"
    },
    "location": {
      "type": "string",
      "defaultValue": "[resourceGroup().location]"
    },
    "nodeCount": {
      "type": "int",
      "defaultValue": 3
    }
  },
  "resources": [
    {
      "type": "Microsoft.ContainerService/managedClusters",
      "apiVersion": "2023-03-01",
      "name": "[parameters('clusterName')]",
      "location": "[parameters('location')]",
      "properties": {
        "dnsPrefix": "[parameters('clusterName')]",
        "agentPoolProfiles": [
          {
            "name": "nodepool1",
            "count": "[parameters('nodeCount')]",
            "vmSize": "Standard_D2s_v3",
            "osType": "Linux",
            "mode": "System"
          }
        ],
        "servicePrincipalProfile": {
          "clientId": "[parameters('servicePrincipalClientId')]",
          "secret": "[parameters('servicePrincipalClientSecret')]"
        }
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "apiVersion": "2022-12-01",
      "name": "semantic-layer-postgres",
      "location": "[parameters('location')]",
      "properties": {
        "administratorLogin": "postgres",
        "administratorLoginPassword": "[parameters('postgresPassword')]",
        "version": "15",
        "storage": {
          "storageSizeGB": 128
        },
        "compute": {
          "tier": "GeneralPurpose",
          "name": "Standard_D2s_v3"
        }
      }
    }
  ]
}
```

Deploy with Azure CLI:

```bash
# Create resource group
az group create --name semantic-layer-rg --location eastus

# Deploy infrastructure
az deployment group create \
  --resource-group semantic-layer-rg \
  --template-file azuredeploy.json \
  --parameters @azuredeploy.parameters.json

# Get AKS credentials
az aks get-credentials --resource-group semantic-layer-rg --name semantic-layer-aks
```

### Google Cloud Deployment

#### GKE with Cloud Deployment Manager

Create `deployment.yaml`:

```yaml
imports:
- path: cluster.jinja

resources:
- name: semantic-layer-cluster
  type: cluster.jinja
  properties:
    zone: us-central1-a
    cluster:
      name: semantic-layer-gke
      initialNodeCount: 3
      nodeConfig:
        machineType: n1-standard-2
        diskSizeGb: 100
        oauthScopes:
        - https://www.googleapis.com/auth/cloud-platform

- name: semantic-layer-postgres
  type: sqladmin.v1beta4.instance
  properties:
    region: us-central1
    settings:
      tier: db-n1-standard-2
      dataDiskSizeGb: 100
      backupConfiguration:
        enabled: true
      ipConfiguration:
        authorizedNetworks: []
        ipv4Enabled: true
        requireSsl: true
```

Deploy with gcloud:

```bash
# Deploy infrastructure
gcloud deployment-manager deployments create semantic-layer \
  --config deployment.yaml

# Get GKE credentials
gcloud container clusters get-credentials semantic-layer-gke \
  --zone us-central1-a
```

---

## On-Premises Deployment

### System Preparation

#### 1. Server Setup

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Java 17
sudo apt install openjdk-17-jdk -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

#### 2. Database Setup

```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# Configure PostgreSQL
sudo -u postgres psql << EOF
CREATE DATABASE semantic_layer;
CREATE USER semantic_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE semantic_layer TO semantic_user;
\q
EOF

# Configure PostgreSQL for remote connections
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/*/main/postgresql.conf
echo "host all all 0.0.0.0/0 md5" | sudo tee -a /etc/postgresql/*/main/pg_hba.conf

# Restart PostgreSQL
sudo systemctl restart postgresql
```

#### 3. Redis Setup

```bash
# Install Redis
sudo apt install redis-server -y

# Configure Redis
sudo sed -i 's/bind 127.0.0.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf
sudo sed -i 's/# requirepass foobared/requirepass your_redis_password/' /etc/redis/redis.conf

# Restart Redis
sudo systemctl restart redis-server
```

### Application Deployment

#### 1. Download and Extract

```bash
# Download application
wget https://github.com/your-org/semantic-layer/releases/latest/download/semantic-layer.tar.gz

# Extract
tar -xzf semantic-layer.tar.gz
cd semantic-layer
```

#### 2. Configuration

Create `application.properties`:

```properties
# Server Configuration
server.port=8080
server.address=0.0.0.0

# Database Configuration
spring.datasource.url=jdbc:postgresql://localhost:5432/semantic_layer
spring.datasource.username=semantic_user
spring.datasource.password=secure_password
spring.datasource.driver-class-name=org.postgresql.Driver

# Connection Pool
spring.datasource.hikari.maximum-pool-size=20
spring.datasource.hikari.minimum-idle=5
spring.datasource.hikari.connection-timeout=20000

# Redis Configuration
spring.redis.host=localhost
spring.redis.port=6379
spring.redis.password=your_redis_password
spring.redis.timeout=2000ms

# Logging
logging.level.root=INFO
logging.level.com.semanticlayer=DEBUG
logging.file.name=logs/application.log

# Security
jwt.secret=your_jwt_secret_key_here
jwt.expiration=86400

# Management Endpoints
management.endpoints.web.exposure.include=health,info,metrics
management.endpoint.health.show-details=always
```

#### 3. Service Configuration

Create systemd service `/etc/systemd/system/semantic-layer.service`:

```ini
[Unit]
Description=Universal Semantic Layer Application
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=semantic
Group=semantic
WorkingDirectory=/opt/semantic-layer
ExecStart=/usr/bin/java -jar -Xms2g -Xmx4g semantic-layer.jar
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s

Environment=JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
Environment=SPRING_PROFILES_ACTIVE=production

StandardOutput=journal
StandardError=journal
SyslogIdentifier=semantic-layer

[Install]
WantedBy=multi-user.target
```

#### 4. Start Services

```bash
# Create user and directories
sudo useradd -r -s /bin/false semantic
sudo mkdir -p /opt/semantic-layer/logs
sudo chown -R semantic:semantic /opt/semantic-layer

# Copy application files
sudo cp -r * /opt/semantic-layer/
sudo chown -R semantic:semantic /opt/semantic-layer

# Enable and start service
sudo systemctl enable semantic-layer
sudo systemctl start semantic-layer

# Check status
sudo systemctl status semantic-layer
```

### Load Balancer Setup

#### Nginx Configuration

```nginx
upstream semantic_layer_backend {
    server 127.0.0.1:8080;
    # Add more servers for clustering
    # server 192.168.1.101:8080;
    # server 192.168.1.102:8080;
}

server {
    listen 80;
    server_name semantic.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name semantic.yourdomain.com;

    ssl_certificate /etc/ssl/certs/semantic.crt;
    ssl_certificate_key /etc/ssl/private/semantic.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

    location / {
        proxy_pass http://semantic_layer_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://semantic_layer_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/v1/auth/login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://semantic_layer_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support for real-time features
    location /ws/ {
        proxy_pass http://semantic_layer_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        proxy_pass http://semantic_layer_backend;
    }
}
```

---

## Configuration Management

### Environment-Specific Configurations

#### Development Environment

```yaml
# config/development.yml
server:
  port: 8080
  
spring:
  profiles:
    active: development
  datasource:
    url: jdbc:postgresql://localhost:5432/semantic_layer_dev
    username: dev_user
    password: dev_password
  redis:
    host: localhost
    port: 6379
    
logging:
  level:
    com.semanticlayer: DEBUG
    org.springframework.web: DEBUG
    
management:
  endpoints:
    web:
      exposure:
        include: "*"
```

#### Production Environment

```yaml
# config/production.yml
server:
  port: 8080
  
spring:
  profiles:
    active: production
  datasource:
    url: ${DATABASE_URL}
    username: ${DATABASE_USERNAME}
    password: ${DATABASE_PASSWORD}
    hikari:
      maximum-pool-size: 50
      minimum-idle: 10
  redis:
    host: ${REDIS_HOST}
    port: ${REDIS_PORT}
    password: ${REDIS_PASSWORD}
    
logging:
  level:
    root: INFO
  file:
    name: /var/log/semantic-layer/application.log
    
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
```

### Configuration Validation

```bash
#!/bin/bash
# validate-config.sh

echo "Validating configuration..."

# Check required environment variables
required_vars=("DATABASE_URL" "REDIS_URL" "JWT_SECRET")
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "ERROR: $var is not set"
        exit 1
    fi
done

# Test database connection
echo "Testing database connection..."
java -cp semantic-layer.jar org.springframework.boot.loader.JarLauncher --spring.profiles.active=production --validate-config-only

# Test Redis connection
echo "Testing Redis connection..."
redis-cli -h $REDIS_HOST -p $REDIS_PORT -a $REDIS_PASSWORD ping

echo "Configuration validation completed successfully"
```

---

## Security Setup

### SSL/TLS Configuration

#### Certificate Generation

```bash
# Generate self-signed certificate (development only)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# For production, use Let's Encrypt
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d semantic.yourdomain.com
```

#### SSL Configuration in Application

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12
    key-alias: semantic-layer
```

### Firewall Configuration

```bash
# UFW firewall rules
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow ssh

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow application port (if direct access needed)
sudo ufw allow 8080/tcp

# Allow database access from application servers only
sudo ufw allow from 192.168.1.0/24 to any port 5432

# Check status
sudo ufw status verbose
```

### Security Hardening

#### System Hardening

```bash
# Disable unnecessary services
sudo systemctl disable apache2 2>/dev/null || true
sudo systemctl disable nginx 2>/dev/null || true

# Configure fail2ban
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Update packages regularly
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y
```

#### Application Security

```properties
# application-security.properties

# Security headers
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.http-only=true
server.servlet.session.tracking-modes=cookie

# CORS configuration
cors.allowed-origins=https://yourdomain.com
cors.allowed-methods=GET,POST,PUT,DELETE,OPTIONS
cors.allowed-headers=*
cors.max-age=3600

# Rate limiting
rate-limit.requests-per-minute=60
rate-limit.burst-capacity=100

# Authentication
jwt.secret=${JWT_SECRET}
jwt.expiration=3600
jwt.refresh-expiration=86400
```

---

## Monitoring and Logging

### Prometheus Configuration

#### Application Metrics

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "semantic_layer_rules.yml"

scrape_configs:
  - job_name: 'semantic-layer'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/actuator/prometheus'
    scrape_interval: 30s

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['localhost:9187']

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['localhost:9121']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

#### Alert Rules

```yaml
# semantic_layer_rules.yml
groups:
- name: semantic_layer_alerts
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"

  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.8
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage"
      description: "Memory usage is above 80%"

  - alert: DatabaseConnectionFailure
    expr: up{job="postgres-exporter"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Database connection failure"
      description: "Cannot connect to PostgreSQL database"
```

### Grafana Dashboards

#### Application Dashboard JSON

```json
{
  "dashboard": {
    "title": "Semantic Layer Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{uri}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "jvm_memory_used_bytes / jvm_memory_max_bytes",
            "legendFormat": "{{area}}"
          }
        ]
      }
    ]
  }
}
```

### Centralized Logging

#### ELK Stack Configuration

```yaml
# docker-compose.logging.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"

  logstash:
    image: docker.elastic.co/logstash/logstash:8.8.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.8.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch

volumes:
  elasticsearch_data:
```

#### Logstash Configuration

```ruby
# logstash.conf
input {
  beats {
    port => 5044
  }
  
  tcp {
    port => 5000
    codec => json_lines
  }
}

filter {
  if [fields][service] == "semantic-layer" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{DATA:thread} %{DATA:logger} - %{GREEDYDATA:message}" }
    }
    
    date {
      match => [ "timestamp", "yyyy-MM-dd HH:mm:ss.SSS" ]
    }
    
    if [level] == "ERROR" {
      mutate {
        add_tag => [ "error" ]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "semantic-layer-%{+YYYY.MM.dd}"
  }
  
  stdout {
    codec => rubydebug
  }
}
```

---

## Backup and Recovery

### Database Backup

#### Automated Backup Script

```bash
#!/bin/bash
# backup-database.sh

DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="semantic_layer"
DB_USER="semantic_user"
BACKUP_DIR="/opt/backups/postgres"
RETENTION_DAYS=30

# Create backup directory
mkdir -p $BACKUP_DIR

# Generate backup filename
BACKUP_FILE="$BACKUP_DIR/semantic_layer_$(date +%Y%m%d_%H%M%S).sql"

# Create backup
pg_dump -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME > $BACKUP_FILE

# Compress backup
gzip $BACKUP_FILE

# Remove old backups
find $BACKUP_DIR -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_FILE.gz"
```

#### Backup Scheduling

```bash
# Add to crontab
crontab -e

# Daily backup at 2 AM
0 2 * * * /opt/scripts/backup-database.sh

# Weekly full backup
0 1 * * 0 /opt/scripts/backup-full.sh
```

### Application Data Backup

```bash
#!/bin/bash
# backup-application.sh

APP_DIR="/opt/semantic-layer"
BACKUP_DIR="/opt/backups/application"
CONFIG_DIR="/etc/semantic-layer"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Backup configuration
tar -czf "$BACKUP_DIR/config_$TIMESTAMP.tar.gz" -C $CONFIG_DIR .

# Backup logs
tar -czf "$BACKUP_DIR/logs_$TIMESTAMP.tar.gz" -C $APP_DIR logs/

# Backup custom models and user data
tar -czf "$BACKUP_DIR/data_$TIMESTAMP.tar.gz" -C $APP_DIR data/

echo "Application backup completed"
```

### Disaster Recovery Plan

#### Recovery Procedures

```bash
#!/bin/bash
# disaster-recovery.sh

BACKUP_DATE=${1:-$(date +%Y%m%d)}
BACKUP_DIR="/opt/backups"

echo "Starting disaster recovery for date: $BACKUP_DATE"

# 1. Stop application
sudo systemctl stop semantic-layer

# 2. Restore database
echo "Restoring database..."
gunzip < "$BACKUP_DIR/postgres/semantic_layer_${BACKUP_DATE}*.sql.gz" | psql -h localhost -U semantic_user -d semantic_layer

# 3. Restore application data
echo "Restoring application data..."
tar -xzf "$BACKUP_DIR/application/data_${BACKUP_DATE}*.tar.gz" -C /opt/semantic-layer/

# 4. Restore configuration
echo "Restoring configuration..."
tar -xzf "$BACKUP_DIR/application/config_${BACKUP_DATE}*.tar.gz" -C /etc/semantic-layer/

# 5. Start application
sudo systemctl start semantic-layer

# 6. Verify recovery
sleep 30
curl -f http://localhost:8080/health || echo "Health check failed"

echo "Disaster recovery completed"
```

---

## Performance Tuning

### JVM Tuning

#### Production JVM Settings

```bash
# /etc/systemd/system/semantic-layer.service
[Service]
Environment="JAVA_OPTS=-Xms4g -Xmx8g -XX:+UseG1GC -XX:G1HeapRegionSize=16m -XX:+UseStringDeduplication -XX:+OptimizeStringConcat -XX:MaxGCPauseMillis=200 -XX:ParallelGCThreads=4 -XX:ConcGCThreads=2 -XX:InitiatingHeapOccupancyPercent=45 -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/opt/semantic-layer/logs/heapdump.hprof"
ExecStart=/usr/bin/java $JAVA_OPTS -jar semantic-layer.jar
```

### Database Performance

#### PostgreSQL Tuning

```sql
-- postgresql.conf optimizations
shared_buffers = 1GB
effective_cache_size = 3GB
maintenance_work_mem = 256MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 4MB
min_wal_size = 1GB
max_wal_size = 4GB
max_worker_processes = 8
max_parallel_workers_per_gather = 4
max_parallel_workers = 8
max_parallel_maintenance_workers = 4
```

#### Index Optimization

```sql
-- Create performance indexes
CREATE INDEX CONCURRENTLY idx_queries_user_id ON queries(user_id);
CREATE INDEX CONCURRENTLY idx_queries_created_at ON queries(created_at);
CREATE INDEX CONCURRENTLY idx_models_org_id ON models(organization_id);
CREATE INDEX CONCURRENTLY idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Composite indexes for common queries
CREATE INDEX CONCURRENTLY idx_models_org_type ON models(organization_id, model_type);
CREATE INDEX CONCURRENTLY idx_queries_user_status ON queries(user_id, status);
```

### Application Performance

#### Connection Pool Tuning

```yaml
spring:
  datasource:
    hikari:
      maximum-pool-size: 50
      minimum-idle: 10
      connection-timeout: 20000
      idle-timeout: 300000
      max-lifetime: 1200000
      leak-detection-threshold: 60000
```

#### Cache Configuration

```yaml
spring:
  cache:
    type: redis
    redis:
      time-to-live: 600s
      cache-null-values: false
  redis:
    timeout: 2000ms
    lettuce:
      pool:
        max-active: 50
        max-idle: 10
        min-idle: 5
```

---

## Troubleshooting

### Common Issues

#### Application Won't Start

```bash
# Check Java version
java -version

# Check port availability
netstat -tlnp | grep :8080

# Check logs
tail -f /opt/semantic-layer/logs/application.log

# Check system resources
free -h
df -h
```

#### Database Connection Issues

```bash
# Test database connectivity
psql -h localhost -U semantic_user -d semantic_layer -c "SELECT 1;"

# Check PostgreSQL status
sudo systemctl status postgresql

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*-main.log

# Check connection limits
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity;"
```

#### Performance Issues

```bash
# Monitor system resources
htop
iotop
netstat -i

# Check Java heap usage
jstat -gc <pid>

# Monitor database performance
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity WHERE state = 'active';"

# Check slow queries
sudo -u postgres psql -c "SELECT query, calls, total_time, mean_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
```

### Log Analysis

#### Error Pattern Analysis

```bash
# Find error patterns
grep "ERROR" /opt/semantic-layer/logs/application.log | cut -d' ' -f4- | sort | uniq -c | sort -nr

# Monitor failed requests
grep "status=5" /var/log/nginx/access.log | wc -l

# Check memory issues
grep "OutOfMemoryError" /opt/semantic-layer/logs/application.log
```

### Health Checks

#### Automated Health Monitoring

```bash
#!/bin/bash
# health-check.sh

ENDPOINT="http://localhost:8080/health"
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Check application health
if ! curl -f $ENDPOINT > /dev/null 2>&1; then
    echo "Health check failed at $(date)"
    
    # Send alert to Slack
    curl -X POST -H 'Content-type: application/json' \
        --data '{"text":"🚨 Semantic Layer health check failed!"}' \
        $SLACK_WEBHOOK
    
    # Restart application if needed
    sudo systemctl restart semantic-layer
    
    exit 1
fi

echo "Health check passed at $(date)"
```
