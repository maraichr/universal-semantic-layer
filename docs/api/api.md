# API Reference Documentation

## Overview

The Universal Semantic Layer Application provides comprehensive REST and GraphQL APIs for managing semantic models, executing queries, and administering the system. All APIs use JSON for data exchange and support standard HTTP status codes.

## Base URL

```
Production: https://api.yourdomain.com/v1
Development: http://localhost:8080/api/v1
```

## Authentication

The API uses OAuth 2.0 / OpenID Connect for authentication, delegated to an external identity provider.

### Obtaining Access Tokens

#### Development (Keycloak)
```bash
# Get token using Resource Owner Password Credentials (dev only)
curl -X POST http://localhost:8180/realms/semantic-layer/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=semantic-layer-frontend" \
  -d "username=user@example.com" \
  -d "password=password"

# Response
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "token_type": "Bearer"
}
```

#### Production (Auth0/Okta)
```bash
# Use authorization code flow with PKCE
# Redirect user to:
https://your-domain.auth0.com/authorize?\
response_type=code&\
client_id=YOUR_CLIENT_ID&\
redirect_uri=https://your-app.com/callback&\
scope=openid%20profile%20email&\
code_challenge=GENERATED_CODE_CHALLENGE&\
code_challenge_method=S256

# Exchange code for token
curl -X POST https://your-domain.auth0.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "client_id": "YOUR_CLIENT_ID",
    "code": "AUTHORIZATION_CODE",
    "redirect_uri": "https://your-app.com/callback",
    "code_verifier": "CODE_VERIFIER"
  }'
```

### Using Tokens with Kong Gateway

```bash
# All API requests go through Kong Gateway
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:8000/api/v1/models
```

## Data Sources API

### List Data Sources
```bash
GET /data-sources
```

**Parameters:**
- `page` (integer): Page number (default: 1)
- `limit` (integer): Items per page (default: 20)
- `search` (string): Search term
- `type` (string): Filter by source type

**Response:**
```json
{
  "data": [
    {
      "id": "ds_123",
      "name": "Sales Database",
      "type": "postgresql",
      "status": "connected",
      "connection_string": "postgresql://localhost:5432/sales",
      "created_at": "2025-01-15T10:30:00Z",
      "updated_at": "2025-01-15T10:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

### Create Data Source
```bash
POST /data-sources
Content-Type: application/json

{
  "name": "Customer Database",
  "type": "mysql",
  "connection_string": "mysql://user:pass@localhost:3306/customers",
  "credentials": {
    "username": "db_user",
    "password": "db_password"
  },
  "properties": {
    "ssl_enabled": true,
    "timeout": 30
  }
}
```

### Get Data Source
```bash
GET /data-sources/{id}
```

### Update Data Source
```bash
PUT /data-sources/{id}
Content-Type: application/json

{
  "name": "Updated Database Name",
  "properties": {
    "timeout": 60
  }
}
```

### Delete Data Source
```bash
DELETE /data-sources/{id}
```

### Test Connection
```bash
POST /data-sources/{id}/test-connection
```

## Physical Models API

### List Physical Models
```bash
GET /physical-models
```

### Create Physical Model
```bash
POST /physical-models
Content-Type: application/json

{
  "name": "Sales Physical Model",
  "data_source_id": "ds_123",
  "tables": [
    {
      "name": "customers",
      "columns": [
        {
          "name": "customer_id",
          "type": "integer",
          "is_primary_key": true,
          "is_nullable": false
        },
        {
          "name": "customer_name",
          "type": "varchar",
          "length": 255,
          "is_nullable": false
        }
      ]
    }
  ],
  "relationships": [
    {
      "from_table": "orders",
      "from_column": "customer_id",
      "to_table": "customers",
      "to_column": "customer_id",
      "type": "many_to_one"
    }
  ]
}
```

### Import Schema
```bash
POST /physical-models/import-schema
Content-Type: application/json

{
  "data_source_id": "ds_123",
  "schema_name": "public",
  "include_tables": ["customers", "orders", "products"],
  "auto_detect_relationships": true
}
```

## Business Models API

### List Business Models
```bash
GET /business-models
```

### Create Business Model
```bash
POST /business-models
Content-Type: application/json

{
  "name": "Sales Business Model",
  "description": "Business view of sales data",
  "physical_model_id": "pm_123",
  "entities": [
    {
      "name": "Customer",
      "description": "Customer entity",
      "physical_table": "customers",
      "attributes": [
        {
          "name": "customerId",
          "display_name": "Customer ID",
          "physical_column": "customer_id",
          "data_type": "integer",
          "is_key": true
        },
        {
          "name": "customerName",
          "display_name": "Customer Name",
          "physical_column": "customer_name",
          "data_type": "string"
        }
      ]
    }
  ],
  "metrics": [
    {
      "name": "totalRevenue",
      "display_name": "Total Revenue",
      "formula": "SUM(order_amount)",
      "data_type": "decimal",
      "aggregation": "sum"
    }
  ],
  "hierarchies": [
    {
      "name": "dateHierarchy",
      "display_name": "Date Hierarchy",
      "levels": [
        {"name": "year", "attribute": "order_year"},
        {"name": "quarter", "attribute": "order_quarter"},
        {"name": "month", "attribute": "order_month"}
      ]
    }
  ]
}
```

## Presentation Models API

### List Presentation Models
```bash
GET /presentation-models
```

### Create Presentation Model
```bash
POST /presentation-models
Content-Type: application/json

{
  "name": "Executive Dashboard",
  "description": "High-level sales metrics for executives",
  "business_model_id": "bm_123",
  "subject_areas": [
    {
      "name": "Sales Performance",
      "entities": ["Customer", "Order"],
      "metrics": ["totalRevenue", "orderCount"],
      "filters": [
        {
          "attribute": "order_date",
          "operator": "greater_than",
          "value": "2024-01-01"
        }
      ]
    }
  ],
  "perspectives": [
    {
      "name": "Regional View",
      "description": "Sales data grouped by region",
      "default_dimensions": ["Customer.region"],
      "default_metrics": ["totalRevenue"],
      "security_rules": [
        {
          "role": "regional_manager",
          "filter": "Customer.region = @user.region"
        }
      ]
    }
  ]
}
```

## Query API

### Execute Query
```bash
POST /queries/execute
Content-Type: application/json

{
  "presentation_model_id": "pm_123",
  "select": [
    "Customer.customerName",
    "Customer.region",
    "Metrics.totalRevenue"
  ],
  "filters": [
    {
      "field": "Customer.region",
      "operator": "in",
      "values": ["North", "South"]
    },
    {
      "field": "Order.orderDate",
      "operator": "between",
      "values": ["2024-01-01", "2024-12-31"]
    }
  ],
  "group_by": ["Customer.customerName", "Customer.region"],
  "order_by": [
    {
      "field": "Metrics.totalRevenue",
      "direction": "desc"
    }
  ],
  "limit": 100,
  "offset": 0
}
```

**Response:**
```json
{
  "query_id": "q_789",
  "execution_time_ms": 245,
  "row_count": 25,
  "columns": [
    {
      "name": "Customer.customerName",
      "display_name": "Customer Name",
      "data_type": "string"
    },
    {
      "name": "Customer.region",
      "display_name": "Region",
      "data_type": "string"
    },
    {
      "name": "Metrics.totalRevenue",
      "display_name": "Total Revenue",
      "data_type": "decimal"
    }
  ],
  "data": [
    {
      "Customer.customerName": "Acme Corp",
      "Customer.region": "North",
      "Metrics.totalRevenue": 150000.00
    }
  ],
  "sql_query": "SELECT c.customer_name, c.region, SUM(o.order_amount) FROM..."
}
```

### Validate Query
```bash
POST /queries/validate
Content-Type: application/json

{
  "presentation_model_id": "pm_123",
  "select": ["Customer.customerName"],
  "filters": [
    {
      "field": "Customer.invalidField",
      "operator": "equals",
      "value": "test"
    }
  ]
}
```

### Get Query History
```bash
GET /queries/history?user_id=user_123&limit=50
```

### Save Query
```bash
POST /queries/saved
Content-Type: application/json

{
  "name": "Top Customers by Revenue",
  "description": "Query to find top customers",
  "query": {
    "presentation_model_id": "pm_123",
    "select": ["Customer.customerName", "Metrics.totalRevenue"],
    "order_by": [{"field": "Metrics.totalRevenue", "direction": "desc"}],
    "limit": 10
  },
  "is_public": false
}
```

## User Management API

### List Users
```bash
GET /users
```

### Create User
```bash
POST /users
Content-Type: application/json

{
  "username": "john.doe",
  "email": "john.doe@company.com",
  "first_name": "John",
  "last_name": "Doe",
  "roles": ["analyst", "viewer"],
  "attributes": {
    "department": "Sales",
    "region": "North"
  }
}
```

### Update User
```bash
PUT /users/{id}
Content-Type: application/json

{
  "roles": ["analyst", "power_user"],
  "attributes": {
    "department": "Marketing"
  }
}
```

## Role Management API

### List Roles
```bash
GET /roles
```

### Create Role
```bash
POST /roles
Content-Type: application/json

{
  "name": "regional_analyst",
  "display_name": "Regional Analyst",
  "description": "Analyst with regional data access",
  "permissions": [
    "query:execute",
    "model:read",
    "dashboard:create"
  ],
  "data_access_rules": [
    {
      "entity": "Customer",
      "filter": "region = @user.region"
    }
  ]
}
```

## Error Handling

The API uses standard HTTP status codes and returns detailed error information:

### Error Response Format
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid query syntax",
    "details": [
      {
        "field": "filters[0].operator",
        "message": "Unsupported operator 'contains'"
      }
    ],
    "request_id": "req_123456"
  }
}
```

### Common Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `422` - Validation Error
- `429` - Rate Limited
- `500` - Internal Server Error

## Rate Limiting

API endpoints are rate limited:
- **Default**: 1000 requests per hour per user
- **Query execution**: 100 requests per hour per user
- **Admin operations**: 50 requests per hour per user

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## GraphQL API

### Endpoint
```
POST /graphql
```

### Example Query
```graphql
query GetBusinessModel($id: ID!) {
  businessModel(id: $id) {
    id
    name
    description
    entities {
      name
      displayName
      attributes {
        name
        displayName
        dataType
      }
    }
    metrics {
      name
      displayName
      formula
      aggregation
    }
  }
}
```

### Example Mutation
```graphql
mutation CreateEntity($input: EntityInput!) {
  createEntity(input: $input) {
    id
    name
    attributes {
      id
      name
      dataType
    }
  }
}
```

### GraphQL Schema Introspection
```graphql
query IntrospectionQuery {
  __schema {
    types {
      name
      description
    }
  }
}
```

## SDK Examples

### JavaScript SDK
```javascript
import SemanticLayer from '@your-org/semantic-layer-js';

const client = new SemanticLayer({
  baseUrl: 'https://api.yourdomain.com/v1',
  apiKey: 'your_api_key'
});

// Execute a query
const results = await client.queries.execute({
  presentationModelId: 'pm_123',
  select: ['Customer.customerName', 'Metrics.totalRevenue'],
  filters: [
    { field: 'Customer.region', operator: 'equals', value: 'North' }
  ]
});
```

### Python SDK
```python
from semantic_layer import SemanticLayerClient

client = SemanticLayerClient(
    base_url='https://api.yourdomain.com/v1',
    api_key='your_api_key'
)

# Execute a query
results = client.queries.execute({
    'presentation_model_id': 'pm_123',
    'select': ['Customer.customerName', 'Metrics.totalRevenue'],
    'filters': [
        {'field': 'Customer.region', 'operator': 'equals', 'value': 'North'}
    ]
})
```

## Webhooks

### Configure Webhooks
```bash
POST /webhooks
Content-Type: application/json

{
  "url": "https://your-app.com/webhook",
  "events": ["model.created", "query.executed"],
  "secret": "webhook_secret",
  "active": true
}
```

### Webhook Events
- `model.created` - New model created
- `model.updated` - Model updated
- `model.deleted` - Model deleted
- `query.executed` - Query executed
- `user.created` - User created
- `role.assigned` - Role assigned to user

### Webhook Payload Example
```json
{
  "event": "model.created",
  "timestamp": "2025-01-15T10:30:00Z",
  "data": {
    "model_id": "bm_123",
    "model_name": "Sales Model",
    "created_by": "user_456"
  },
  "webhook_id": "wh_789"
}
```

## API Versioning

The API supports versioning through URL paths:
- `/v1/` - Current stable version
- `/v2/` - Next version (beta)

Version deprecation notices are provided in response headers:
```
X-API-Version: v1
X-API-Deprecated: false
X-API-Sunset: 2026-01-01
```

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
- JSON: `/api/v1/openapi.json`
- YAML: `/api/v1/openapi.yaml`
- Swagger UI: `/swagger-ui`
