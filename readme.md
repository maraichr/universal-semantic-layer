# Universal Semantic Layer Application

A comprehensive platform that enables organizations to create a unified, business-friendly view of their data through a three-layer modeling approach: physical, business, and presentation layers.

## Overview

The Universal Semantic Layer Application provides a robust abstraction layer between data sources and business users, enabling consistent data access, improved governance, and self-service analytics capabilities. The platform transforms complex technical data structures into intuitive business models that non-technical users can easily understand and query.

## Key Features

### 🏗️ Three-Layer Architecture
- **Physical Layer**: Direct representation of data sources and their technical structure
- **Business Layer**: Business-friendly entities, attributes, and metrics
- **Presentation Layer**: Customized views and subject areas for different user groups

### 🔐 Advanced Security
- Role-based access control (RBAC) with fine-grained permissions
- Row-level and column-level security
- Data masking and privacy controls
- Enterprise SSO integration (SAML, OAuth, OpenID Connect)

### 🔌 Extensive Integrations
- **BI Tools**: Tableau, Power BI, Looker, Qlik
- **Databases**: PostgreSQL, MySQL, SQL Server, Oracle, MongoDB
- **Data Warehouses**: Snowflake, Redshift, BigQuery, Azure Synapse
- **Cloud Storage**: S3, Google Cloud Storage, Azure Blob Storage

### ⚡ High Performance
- Intelligent query optimization and routing
- Multi-level caching (metadata, query results, authentication)
- Connection pooling and resource management
- Horizontal and vertical scaling capabilities

### 🔧 Developer-Friendly
- RESTful and GraphQL APIs
- SDKs for JavaScript, Python, Java, .NET
- JDBC/ODBC drivers for standard connectivity
- Comprehensive OpenAPI documentation

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Layer                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Web UI      │  │ BI Tools    │  │ Custom Apps │              │
│  │ (React)     │  │ (Connectors)│  │ (via API)   │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                               │
                               │ HTTPS/REST
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      API Gateway Layer                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Auth        │  │ Rate Limit  │  │ API Version │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Modeling    │  │ Query       │  │ Admin       │              │
│  │ Services    │  │ Services    │  │ Services    │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Data Layer                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Metadata    │  │ Query       │  │ Caching     │              │
│  │ Repository  │  │ Engine      │  │ System      │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## Technology Stack

### Backend
- **Languages**: Java/Kotlin, Python
- **Frameworks**: Spring Boot, FastAPI
- **Database**: PostgreSQL
- **Caching**: Redis
- **Message Broker**: Apache Kafka
- **API Gateway**: Kong

### Frontend
- **Framework**: React with TypeScript
- **State Management**: Redux, Context API
- **UI Components**: Material-UI
- **Visualization**: D3.js
- **Build Tools**: Webpack, Babel

### DevOps
- **Containerization**: Docker
- **Orchestration**: Kubernetes
- **CI/CD**: Jenkins, GitHub Actions
- **Infrastructure**: Terraform
- **Monitoring**: Prometheus, Grafana
- **Logging**: ELK Stack

## Getting Started

### Prerequisites

- **Development Environment**:
  - WSL2 with Ubuntu 20.04 or 22.04
  - Docker Desktop for Windows with WSL2 backend enabled
  - Cursor IDE configured for WSL2 development
  - Node.js 18+ and npm/yarn
  - Java 17+ and Maven/Gradle
  - Python 3.9+
  - kubectl and helm (for Kubernetes deployments)

- **Local Development Services**:
  - Docker and Docker Compose
  - Keycloak 22+ (via Docker)
  - Kong Gateway 3.4+ (via Docker)
  - PostgreSQL 13+
  - Redis 6+

### WSL2 Development Setup

```bash
# Update WSL2 Ubuntu
sudo apt update && sudo apt upgrade -y

# Install required dependencies
sudo apt install -y build-essential curl git docker.io docker-compose

# Install Java 17
sudo apt install -y openjdk-17-jdk maven

# Install Node.js via nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install 18
nvm use 18

# Configure Docker for WSL2
sudo usermod -aG docker $USER
newgrp docker

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### Quick Start with Docker

Create `docker-compose.yml` for local development:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: semantic_layer
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  keycloak:
    image: quay.io/keycloak/keycloak:22.0
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: postgres
      KC_DB_PASSWORD: postgres
    command: start-dev
    ports:
      - "8180:8080"
    depends_on:
      - postgres

  kong:
    image: kong:3.4-alpine
    environment:
      KONG_DATABASE: postgres
      KONG_PG_HOST: postgres
      KONG_PG_USER: postgres
      KONG_PG_PASSWORD: postgres
      KONG_PG_DATABASE: kong
      KONG_ADMIN_LISTEN: 0.0.0.0:8001
      KONG_PROXY_LISTEN: 0.0.0.0:8000
    ports:
      - "8000:8000"
      - "8001:8001"
    depends_on:
      - postgres
      - kong-migration

  kong-migration:
    image: kong:3.4-alpine
    environment:
      KONG_DATABASE: postgres
      KONG_PG_HOST: postgres
      KONG_PG_USER: postgres
      KONG_PG_PASSWORD: postgres
      KONG_PG_DATABASE: kong
    command: kong migrations bootstrap
    depends_on:
      - postgres

  semantic-layer:
    build: .
    environment:
      DATABASE_URL: postgresql://postgres:postgres@postgres:5432/semantic_layer
      REDIS_URL: redis://redis:6379
      KEYCLOAK_URL: http://keycloak:8080
      KEYCLOAK_REALM: semantic-layer
      KEYCLOAK_CLIENT_ID: semantic-layer-backend
      KONG_ADMIN_URL: http://kong:8001
    ports:
      - "8080:8080"
    depends_on:
      - postgres
      - redis
      - keycloak
      - kong

volumes:
  postgres_data:
  redis_data:
```

```bash
# Clone the repository
git clone https://github.com/your-org/universal-semantic-layer.git
cd universal-semantic-layer

# Start the development environment
docker-compose up -d

# Access the application
# UI: http://localhost:3000 (or other port defined in frontend)
# Backend API: http://localhost:8080
# Keycloak Admin: http://localhost:8180
# Kong Admin API: http://localhost:8001
```

### Manual Installation

```bash
# Backend setup
cd backend
./mvnw spring-boot:run

# Frontend setup
cd frontend
npm install
npm start

# Access the application
open http://localhost:3000
```

### Configuration

Create a `.env` file in the root directory:

```env
# Database
DATABASE_URL=postgresql://localhost:5432/semantic_layer
DATABASE_USERNAME=your_username
DATABASE_PASSWORD=your_password

# Redis
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your_jwt_secret
JWT_EXPIRATION=86400

# External APIs
EXTERNAL_API_KEY=your_api_key
```

## Usage Examples

### Creating a Semantic Model

```javascript
// Connect to a data source
const dataSource = await client.dataSources.create({
  name: "Sales Database",
  type: "postgresql",
  connectionString: "postgresql://localhost:5432/sales"
});

// Define business entities
const customer = await client.entities.create({
  name: "Customer",
  physicalTable: "customers",
  attributes: [
    { name: "customerId", type: "integer", isPrimaryKey: true },
    { name: "customerName", type: "string" },
    { name: "segment", type: "string" }
  ]
});

// Create metrics
const revenue = await client.metrics.create({
  name: "Total Revenue",
  formula: "SUM(order_amount)",
  entity: "Order"
});
```

### Querying Data

```javascript
// Query through the semantic layer
const results = await client.query({
  select: ["Customer.customerName", "Metrics.totalRevenue"],
  filters: [
    { field: "Customer.segment", operator: "equals", value: "Enterprise" }
  ],
  groupBy: ["Customer.customerName"],
  orderBy: [{ field: "Metrics.totalRevenue", direction: "desc" }]
});
```

## API Documentation

The application provides both REST and GraphQL APIs:

- **REST API**: Available at `/api/v1/` with OpenAPI documentation at `/swagger-ui`
- **GraphQL API**: Available at `/graphql` with GraphiQL interface at `/graphiql`

### Authentication

All API requests require authentication via JWT tokens or API keys:

```bash
# Get an access token
curl -X POST /api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "password"}'

# Use the token in subsequent requests
curl -H "Authorization: Bearer <token>" /api/v1/models
```

## Development

### Project Structure

```
universal-semantic-layer/
├── docs/                    # Documentation and specifications
│   ├── architecture.md      # Technical architecture document
│   ├── api/                 # API documentation
│   └── user-guides/         # User documentation
├── backend/                 # Backend services
│   ├── src/main/java/       # Java source code
│   ├── src/main/resources/  # Configuration files
│   └── pom.xml              # Maven configuration
├── frontend/                # React frontend
│   ├── src/                 # Source code
│   ├── public/              # Static assets
│   └── package.json         # NPM configuration
├── infrastructure/          # Infrastructure as Code
│   ├── terraform/           # Terraform configurations
│   └── kubernetes/          # Kubernetes manifests
├── scripts/                 # Build and deployment scripts
└── docker-compose.yml       # Development environment
```

### Running Tests

```bash
# Backend tests
cd backend
./mvnw test

# Frontend tests
cd frontend
npm test

# Integration tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

### Code Quality

We use various tools to maintain code quality:

- **Backend**: Checkstyle, SpotBugs, JaCoCo
- **Frontend**: ESLint, Prettier, Jest
- **Security**: OWASP dependency check, Snyk

```bash
# Run code quality checks
npm run lint
./mvnw checkstyle:check
./mvnw spotbugs:check
```

## Deployment

### Docker Deployment

```bash
# Build and push images
docker build -t your-registry/semantic-layer:latest .
docker push your-registry/semantic-layer:latest

# Deploy with Docker Compose
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f infrastructure/kubernetes/

# Check deployment status
kubectl get pods -n semantic-layer
```

### Cloud Deployment

The application supports deployment on major cloud platforms:

- **AWS**: EKS, RDS, ElastiCache
- **Azure**: AKS, Azure Database, Redis Cache
- **GCP**: GKE, Cloud SQL, Memorystore

See the [deployment guide](docs/deployment.md) for detailed instructions.

## Documentation

Comprehensive documentation is available in the `docs/` folder:

- **[Technical Architecture](docs/architecture.md)**: Detailed technical architecture document
- **[API Reference](docs/api/api.md)**: API Reference documentation
- **[User Guides](docs/user-guides/user-guide.md)**: End-user reference documentation
- **[Deployment Guide](docs/deployment.md)**: Deployment instructions
- **[Security Guide](docs/security.md)**: Security configuration and best practices

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run the test suite: `npm test`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Security

Security is a top priority. Please see our [Security Policy](docs/security.md) for:

- Reporting security vulnerabilities
- Security best practices
- Compliance information

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: Check the `docs/` folder and wiki
- **Issues**: Report bugs and request features via [GitHub Issues](https://github.com/your-org/universal-semantic-layer/issues)
- **Discussions**: Join the conversation in [GitHub Discussions](https://github.com/your-org/universal-semantic-layer/discussions)
- **Enterprise Support**: Contact us at support@your-company.com

## Roadmap

### Current Version (v1.0)
- ✅ Three-layer semantic modeling
- ✅ Role-based access control
- ✅ REST and GraphQL APIs
- ✅ Major BI tool integrations

### Upcoming Features (v1.1)
- 🔄 Advanced analytics and ML integration
- 🔄 Real-time data streaming support
- 🔄 Enhanced visualization capabilities
- 🔄 Multi-tenant architecture

### Future Plans (v2.0)
- 📋 Natural language query interface
- 📋 Automated data discovery
- 📋 Advanced governance workflows
- 📋 Edge computing support

## Acknowledgments

- Built with ❤️ by the Data Platform Team
- Special thanks to our contributors and community
- Inspired by industry best practices and open-source projects

---

**Made with ❤️ for better data accessibility and governance**
