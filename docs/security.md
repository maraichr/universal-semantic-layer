# Security Guide

## Table of Contents

1. [Security Overview](#security-overview)
2. [Authentication](#authentication)
3. [Authorization and Access Control](#authorization-and-access-control)
4. [Data Security](#data-security)
5. [Network Security](#network-security)
6. [Application Security](#application-security)
7. [Infrastructure Security](#infrastructure-security)
8. [Compliance and Governance](#compliance-and-governance)
9. [Security Monitoring and Incident Response](#security-monitoring-and-incident-response)
10. [Security Best Practices](#security-best-practices)
11. [Threat Modeling](#threat-modeling)
12. [Security Testing](#security-testing)

---

## Security Overview

The Universal Semantic Layer Application implements a comprehensive security framework designed to protect data, maintain user privacy, and ensure compliance with industry standards. Security is integrated into every layer of the architecture, from the infrastructure to the application logic.

### Security Principles

- **Defense in Depth**: Multiple layers of security controls
- **Least Privilege**: Users get minimum necessary access
- **Zero Trust**: Never trust, always verify
- **Privacy by Design**: Data protection built into the system
- **Transparency**: Clear audit trails and security visibility
- **Compliance**: Adherence to regulatory requirements

### Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Security Layers                        │
├─────────────────────────────────────────────────────────────────┤
│ Application Security                                            │
│ ├─ Input Validation        ├─ Output Encoding                   │
│ ├─ Authentication         ├─ Session Management                │
│ ├─ Authorization          ├─ Error Handling                    │
├─────────────────────────────────────────────────────────────────┤
│ Data Security                                                   │
│ ├─ Encryption at Rest     ├─ Encryption in Transit            │
│ ├─ Data Classification   ├─ Data Loss Prevention             │
│ ├─ Data Masking          ├─ Key Management                   │
├─────────────────────────────────────────────────────────────────┤
│ Network Security                                                │
│ ├─ Firewalls             ├─ TLS/SSL                           │
│ ├─ VPN/Private Networks  ├─ DDoS Protection                   │
│ ├─ Network Segmentation  ├─ Intrusion Detection              │
├─────────────────────────────────────────────────────────────────┤
│ Infrastructure Security                                         │
│ ├─ OS Hardening          ├─ Container Security                │
│ ├─ Patch Management      ├─ Secrets Management                │
│ ├─ Access Controls       ├─ Security Monitoring               │
└─────────────────────────────────────────────────────────────────┘
```

### Compliance Standards

- **GDPR**: General Data Protection Regulation
- **CCPA**: California Consumer Privacy Act
- **SOX**: Sarbanes-Oxley Act
- **HIPAA**: Health Insurance Portability and Accountability Act
- **SOC 2**: Service Organization Control 2
- **ISO 27001**: Information Security Management

---

## Authentication

### Identity Provider Integration

The Universal Semantic Layer delegates authentication to external identity providers, eliminating the need to manage user credentials directly.

#### Keycloak Configuration (Development)

```yaml
# keycloak-realm-config.json
{
  "realm": "semantic-layer",
  "enabled": true,
  "clients": [
    {
      "clientId": "semantic-layer-backend",
      "enabled": true,
      "protocol": "openid-connect",
      "redirectUris": ["http://localhost:8080/*"],
      "webOrigins": ["http://localhost:3000"],
      "publicClient": false,
      "secret": "${KEYCLOAK_CLIENT_SECRET}"
    },
    {
      "clientId": "semantic-layer-frontend",
      "enabled": true,
      "protocol": "openid-connect",
      "redirectUris": ["http://localhost:3000/*"],
      "webOrigins": ["http://localhost:3000"],
      "publicClient": true
    }
  ],
  "roles": {
    "realm": [
      {"name": "admin"},
      {"name": "data_steward"},
      {"name": "analyst"},
      {"name": "viewer"}
    ]
  }
}
```

#### Spring Security Configuration with Keycloak

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/v1/public/**").permitAll()
                .requestMatchers("/api/v1/admin/**").hasRole("admin")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("realm_access.roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }
}
```

#### Production Identity Providers

For production environments, consider these enterprise identity providers:

1. **Auth0**
   - Universal login
   - Social identity providers
   - Enterprise connections (AD, SAML)
   - Advanced MFA options

2. **Okta**
   - Enterprise SSO
   - Lifecycle management
   - Advanced security policies
   - API access management

3. **Azure Active Directory**
   - Native Microsoft integration
   - Conditional access policies
   - B2B and B2C scenarios
   - Seamless Office 365 integration

---

## Authorization and Access Control

### Role-Based Access Control (RBAC)

#### Role Hierarchy

```yaml
roles:
  admin:
    description: "Full system administration access"
    permissions:
      - "*"
    inherits: []
    
  org_admin:
    description: "Organization administration"
    permissions:
      - "org:*"
      - "user:create"
      - "user:read"
      - "user:update"
      - "role:assign"
    inherits: []
    
  data_steward:
    description: "Data governance and model management"
    permissions:
      - "model:create"
      - "model:read"
      - "model:update"
      - "model:publish"
      - "datasource:create"
      - "datasource:read"
    inherits: []
    
  analyst:
    description: "Data analysis and querying"
    permissions:
      - "model:read"
      - "query:create"
      - "query:read"
      - "query:execute"
      - "dashboard:create"
      - "dashboard:read"
    inherits: []
    
  viewer:
    description: "Read-only access to published content"
    permissions:
      - "model:read"
      - "query:read"
      - "query:execute"
      - "dashboard:read"
    inherits: []
```

#### Permission Implementation

```java
@Entity
@Table(name = "permissions")
public class Permission {
    
    @Id
    private String id;
    
    @Column(nullable = false)
    private String resource;  // e.g., "model", "query", "user"
    
    @Column(nullable = false)
    private String action;    // e.g., "create", "read", "update", "delete"
    
    @Column
    private String scope;     // e.g., "organization", "team", "own"
    
    @Column
    private String condition; // Additional conditions (JSON)
}

@PreAuthorize("hasPermission(#modelId, 'model', 'read')")
public ModelDto getModel(@PathVariable String modelId) {
    return modelService.getModel(modelId);
}
```

### Attribute-Based Access Control (ABAC)

#### Dynamic Access Rules

```java
@Component
public class AccessControlEvaluator {
    
    public boolean evaluate(AccessRequest request) {
        User user = request.getUser();
        Resource resource = request.getResource();
        String action = request.getAction();
        Context context = request.getContext();
        
        // Evaluate based on user attributes
        if (!evaluateUserAttributes(user, resource, action)) {
            return false;
        }
        
        // Evaluate based on resource attributes
        if (!evaluateResourceAttributes(resource, user, action)) {
            return false;
        }
        
        // Evaluate based on environmental context
        if (!evaluateEnvironmentalContext(context, user, resource)) {
            return false;
        }
        
        return true;
    }
    
    private boolean evaluateUserAttributes(User user, Resource resource, String action) {
        // Check user department, level, region, etc.
        if (resource.getType().equals("customer_data")) {
            return user.getDepartment().equals("sales") || 
                   user.getDepartment().equals("marketing");
        }
        return true;
    }
}
```

### Row-Level Security (RLS)

#### Database-Level RLS

```sql
-- Enable RLS on sensitive tables
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

-- Create policies
CREATE POLICY customer_region_policy ON customers
    FOR ALL TO semantic_app_role
    USING (region = current_setting('app.user_region'));

CREATE POLICY sales_rep_policy ON customers
    FOR ALL TO semantic_app_role
    USING (sales_rep_id = current_setting('app.user_id')::bigint);

-- Create policy for managers
CREATE POLICY manager_policy ON customers
    FOR ALL TO semantic_app_role
    USING (
        current_setting('app.user_role') = 'manager'
        OR sales_rep_id = current_setting('app.user_id')::bigint
    );
```

#### Application-Level RLS

```java
@Service
public class DataAccessService {
    
    @Autowired
    private SecurityContextHolder securityContext;
    
    public List<Customer> getCustomers(QueryFilter filter) {
        User currentUser = getCurrentUser();
        
        // Apply row-level security based on user attributes
        if (currentUser.hasRole("REGIONAL_MANAGER")) {
            filter.addCondition("region", "equals", currentUser.getRegion());
        } else if (currentUser.hasRole("SALES_REP")) {
            filter.addCondition("sales_rep_id", "equals", currentUser.getId());
        }
        
        return customerRepository.findWithFilter(filter);
    }
}
```

### Column-Level Security

#### Data Classification

```yaml
data_classification:
  levels:
    public:
      description: "Data that can be shared publicly"
      color: "#green"
    internal:
      description: "Data for internal use only"
      color: "#yellow"
    confidential:
      description: "Sensitive business data"
      color: "#orange"
    restricted:
      description: "Highly sensitive data (PII, financial)"
      color: "#red"
      
  column_classifications:
    customers:
      customer_id: "public"
      customer_name: "internal"
      email: "confidential"
      ssn: "restricted"
      phone: "confidential"
      address: "confidential"
```

#### Column Masking

```java
@Component
public class DataMaskingService {
    
    public Object maskValue(Object value, String classification, User user) {
        if (value == null) return null;
        
        switch (classification) {
            case "restricted":
                if (!user.hasPermission("data:view_restricted")) {
                    return maskRestrictedData(value);
                }
                break;
            case "confidential":
                if (!user.hasPermission("data:view_confidential")) {
                    return maskConfidentialData(value);
                }
                break;
        }
        return value;
    }
    
    private String maskRestrictedData(Object value) {
        String str = value.toString();
        if (str.length() <= 4) return "****";
        return str.substring(0, 2) + "*".repeat(str.length() - 4) + str.substring(str.length() - 2);
    }
    
    private String maskConfidentialData(Object value) {
        String str = value.toString();
        if (str.contains("@")) {
            // Email masking
            String[] parts = str.split("@");
            return parts[0].substring(0, Math.min(3, parts[0].length())) + "***@" + parts[1];
        }
        return str.substring(0, Math.min(3, str.length())) + "***";
    }
}
```

---

## Data Security

### Encryption at Rest

#### Database Encryption

```yaml
# PostgreSQL TDE configuration
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/semantic_layer?ssl=true&sslmode=require
    hikari:
      data-source-properties:
        ssl: true
        sslmode: require
        sslcert: /path/to/client-cert.pem
        sslkey: /path/to/client-key.pem
        sslrootcert: /path/to/ca-cert.pem
```

#### File System Encryption

```bash
# Setup LUKS encryption for data directories
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup open /dev/sdb semantic_data
sudo mkfs.ext4 /dev/mapper/semantic_data
sudo mount /dev/mapper/semantic_data /opt/semantic-layer/data

# Configure automatic mounting
echo "semantic_data /opt/semantic-layer/data ext4 defaults 0 2" >> /etc/fstab
```

#### Application-Level Encryption

```java
@Component
public class FieldEncryptionService {
    
    @Value("${encryption.key}")
    private String encryptionKey;
    
    private final AESUtil aesUtil;
    
    @EventListener
    @Async
    public void encryptSensitiveFields(EntityPrePersistEvent event) {
        Object entity = event.getEntity();
        
        Arrays.stream(entity.getClass().getDeclaredFields())
            .filter(field -> field.isAnnotationPresent(Encrypted.class))
            .forEach(field -> {
                try {
                    field.setAccessible(true);
                    Object value = field.get(entity);
                    if (value != null) {
                        String encrypted = aesUtil.encrypt(value.toString(), encryptionKey);
                        field.set(entity, encrypted);
                    }
                } catch (Exception e) {
                    log.error("Error encrypting field: {}", field.getName(), e);
                }
            });
    }
}

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Encrypted {
    String algorithm() default "AES";
}
```

### Encryption in Transit

#### TLS Configuration

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12
    key-alias: semantic-layer
    protocol: TLS
    enabled-protocols: TLSv1.2,TLSv1.3
    ciphers: 
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
```

#### API Communication Security

```java
@Configuration
public class RestTemplateConfig {
    
    @Bean
    public RestTemplate secureRestTemplate() throws Exception {
        TrustStrategy acceptingTrustStrategy = (cert, authType) -> true;
        SSLContext sslContext = SSLContexts.custom()
                .loadTrustMaterial(null, acceptingTrustStrategy)
                .build();
        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(
                sslContext, 
                new String[]{"TLSv1.2", "TLSv1.3"}, 
                null, 
                SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(csf)
                .build();
        
        HttpComponentsClientHttpRequestFactory requestFactory = 
                new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        
        return new RestTemplate(requestFactory);
    }
}
```

### Key Management

#### AWS KMS Integration

```java
@Service
public class KeyManagementService {
    
    @Autowired
    private AWSKMSClient kmsClient;
    
    @Value("${aws.kms.key-id}")
    private String keyId;
    
    public String encrypt(String plaintext) {
        EncryptRequest request = new EncryptRequest()
                .withKeyId(keyId)
                .withPlaintext(ByteBuffer.wrap(plaintext.getBytes()));
        
        EncryptResult result = kmsClient.encrypt(request);
        return Base64.getEncoder().encodeToString(result.getCiphertextBlob().array());
    }
    
    public String decrypt(String ciphertext) {
        DecryptRequest request = new DecryptRequest()
                .withCiphertextBlob(ByteBuffer.wrap(Base64.getDecoder().decode(ciphertext)));
        
        DecryptResult result = kmsClient.decrypt(request);
        return new String(result.getPlaintext().array());
    }
    
    public void rotateKey() {
        // Implement key rotation logic
        GenerateDataKeyRequest request = new GenerateDataKeyRequest()
                .withKeyId(keyId)
                .withKeySpec("AES_256");
        
        GenerateDataKeyResult result = kmsClient.generateDataKey(request);
        // Store new key securely and update references
    }
}
```

#### HashiCorp Vault Integration

```yaml
spring:
  cloud:
    vault:
      host: vault.company.com
      port: 8200
      scheme: https
      authentication: AWS_IAM
      aws-iam:
        role: semantic-layer-role
      kv:
        enabled: true
        backend: secret
        default-context: semantic-layer
```

### Data Loss Prevention (DLP)

#### Content Scanning

```java
@Component
public class DataLossPreventionScanner {
    
    private static final Pattern SSN_PATTERN = Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b");
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b");
    
    public DlpScanResult scanContent(String content) {
        DlpScanResult result = new DlpScanResult();
        
        // Scan for PII patterns
        if (SSN_PATTERN.matcher(content).find()) {
            result.addViolation("SSN_DETECTED", "Social Security Number detected");
        }
        
        if (CREDIT_CARD_PATTERN.matcher(content).find()) {
            result.addViolation("CREDIT_CARD_DETECTED", "Credit card number detected");
        }
        
        if (EMAIL_PATTERN.matcher(content).find()) {
            result.addViolation("EMAIL_DETECTED", "Email address detected");
        }
        
        return result;
    }
    
    @EventListener
    public void scanQuery(QueryExecutedEvent event) {
        DlpScanResult result = scanContent(event.getQuery());
        if (result.hasViolations()) {
            auditService.logSecurityEvent("DLP_VIOLATION", event.getUserId(), result);
            
            if (result.getSeverity() == Severity.HIGH) {
                // Block query or alert administrators
                throw new SecurityException("Query blocked due to DLP policy violation");
            }
        }
    }
}
```

---

## Network Security

### Firewall Configuration

#### iptables Rules

```bash
#!/bin/bash
# firewall-setup.sh

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (restrict to management network)
iptables -A INPUT -p tcp --dport 22 -s 10.0.1.0/24 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow application port (from load balancer only)
iptables -A INPUT -p tcp --dport 8080 -s 10.0.2.100 -j ACCEPT

# Allow database access (from app servers only)
iptables -A INPUT -p tcp --dport 5432 -s 10.0.2.0/24 -j ACCEPT

# Allow Redis access (from app servers only)
iptables -A INPUT -p tcp --dport 6379 -s 10.0.2.0/24 -j ACCEPT

# Rate limiting for HTTP
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROPPED: "
iptables -A INPUT -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

#### Cloud Security Groups

```terraform
# AWS Security Group
resource "aws_security_group" "semantic_layer_app" {
  name_prefix = "semantic-layer-app"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer.id]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.management_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "semantic-layer-app"
  }
}

resource "aws_security_group" "database" {
  name_prefix = "semantic-layer-db"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.semantic_layer_app.id]
  }

  tags = {
    Name = "semantic-layer-db"
  }
}
```

### DDoS Protection

#### Rate Limiting

```nginx
# nginx.conf
http {
    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=general:10m rate=5r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    
    server {
        listen 443 ssl http2;
        
        # Connection limits
        limit_conn conn_limit_per_ip 20;
        
        location /api/v1/auth/login {
            limit_req zone=login burst=3 nodelay;
            proxy_pass http://backend;
        }
        
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://backend;
        }
        
        location / {
            limit_req zone=general burst=10 nodelay;
            proxy_pass http://backend;
        }
    }
}
```

#### Application-Level Protection

```java
@Component
public class DDoSProtectionFilter implements Filter {
    
    private final RateLimiter rateLimiter;
    private final Map<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String clientIp = getClientIpAddress(httpRequest);
        
        // Check rate limits
        if (!rateLimiter.tryAcquire(clientIp)) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.setStatus(429);
            httpResponse.getWriter().write("Rate limit exceeded");
            return;
        }
        
        // Check for suspicious patterns
        if (isSuspiciousRequest(httpRequest)) {
            log.warn("Suspicious request detected from IP: {}", clientIp);
            // Implement additional checks or blocking
        }
        
        chain.doFilter(request, response);
    }
    
    private boolean isSuspiciousRequest(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String uri = request.getRequestURI();
        
        // Check for common attack patterns
        return userAgent == null || 
               userAgent.toLowerCase().contains("bot") ||
               uri.contains("../") ||
               uri.contains("script") ||
               uri.length() > 1000;
    }
}
```

### VPN and Private Networks

#### WireGuard VPN Setup

```ini
# /etc/wireguard/wg0.conf
[Interface]
PrivateKey = <server-private-key>
Address = 10.8.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Client configurations
[Peer]
PublicKey = <client1-public-key>
AllowedIPs = 10.8.0.2/32

[Peer]
PublicKey = <client2-public-key>
AllowedIPs = 10.8.0.3/32
```

#### Network Segmentation

```yaml
# Kubernetes Network Policies
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: semantic-layer-policy
  namespace: semantic-layer
spec:
  podSelector:
    matchLabels:
      app: semantic-layer
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: database
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector:
        matchLabels:
          name: cache
    ports:
    - protocol: TCP
      port: 6379
  - to: []
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 80
```

---

## Application Security

### Input Validation and Sanitization

#### Comprehensive Input Validation

```java
@Component
public class InputValidator {
    
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "('.+(\\\\x00|\\\\n|\\\\r|\\\\|'|\\\"|\\\\x1a))|" +
        "(.*\\s+(union|select|insert|update|delete|drop|create|alter|exec|execute)\\s+.*)",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(<script[^>]*>.*?</script>)|" +
        "(<.*?javascript:.*?>)|" +
        "(<.*?\\s+on\\w+\\s*=.*?>)",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );
    
    public void validateQuery(String query) throws ValidationException {
        if (query == null || query.trim().isEmpty()) {
            throw new ValidationException("Query cannot be empty");
        }
        
        if (query.length() > 10000) {
            throw new ValidationException("Query too long");
        }
        
        if (SQL_INJECTION_PATTERN.matcher(query).find()) {
            throw new ValidationException("Potential SQL injection detected");
        }
        
        if (XSS_PATTERN.matcher(query).find()) {
            throw new ValidationException("Potential XSS detected");
        }
    }
    
    public String sanitizeInput(String input) {
        if (input == null) return null;
        
        // Remove potential XSS vectors
        String sanitized = input.replaceAll("<script[^>]*>.*?</script>", "")
                               .replaceAll("<.*?javascript:.*?>", "")
                               .replaceAll("<.*?\\s+on\\w+\\s*=.*?>", "");
        
        // Encode HTML entities
        return StringEscapeUtils.escapeHtml4(sanitized);
    }
}

@RestController
public class QueryController {
    
    @Autowired
    private InputValidator validator;
    
    @PostMapping("/api/v1/queries")
    public ResponseEntity<QueryResult> executeQuery(@Valid @RequestBody QueryRequest request) {
        // Validate all inputs
        validator.validateQuery(request.getQuery());
        
        // Sanitize description and metadata
        request.setDescription(validator.sanitizeInput(request.getDescription()));
        
        return ResponseEntity.ok(queryService.execute(request));
    }
}
```

#### Bean Validation

```java
public class QueryRequest {
    
    @NotBlank(message = "Query cannot be empty")
    @Size(max = 10000, message = "Query too long")
    @Pattern(regexp = "^[^<>\"';&|]*$", message = "Invalid characters in query")
    private String query;
    
    @Size(max = 500, message = "Description too long")
    private String description;
    
    @Valid
    @NotNull
    private List<@Valid FilterCriteria> filters;
    
    @Min(1)
    @Max(10000)
    private int limit = 100;
    
    @Min(0)
    private int offset = 0;
}

public class FilterCriteria {
    
    @NotBlank
    @Pattern(regexp = "^[a-zA-Z0-9_.]+$", message = "Invalid field name")
    private String field;
    
    @NotNull
    @Enumerated(EnumType.STRING)
    private FilterOperator operator;
    
    @NotNull
    private Object value;
}
```

### SQL Injection Prevention

#### Parameterized Queries

```java
@Repository
public class CustomerRepository {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // Safe parameterized query
    public List<Customer> findByRegion(String region) {
        String sql = "SELECT * FROM customers WHERE region = ? AND active = ?";
        return jdbcTemplate.query(sql, 
            new Object[]{region, true}, 
            new CustomerRowMapper());
    }
    
    // Dynamic query with whitelist validation
    public List<Customer> findWithDynamicFilter(String sortColumn, String sortDirection) {
        // Validate sort parameters against whitelist
        if (!isValidSortColumn(sortColumn)) {
            throw new IllegalArgumentException("Invalid sort column: " + sortColumn);
        }
        
        if (!Arrays.asList("ASC", "DESC").contains(sortDirection.toUpperCase())) {
            throw new IllegalArgumentException("Invalid sort direction: " + sortDirection);
        }
        
        String sql = String.format("SELECT * FROM customers ORDER BY %s %s", 
            sortColumn, sortDirection);
        
        return jdbcTemplate.query(sql, new CustomerRowMapper());
    }
    
    private boolean isValidSortColumn(String column) {
        Set<String> allowedColumns = Set.of(
            "customer_id", "customer_name", "region", "created_date", "last_updated"
        );
        return allowedColumns.contains(column);
    }
}
```

#### Query Builder Security

```java
@Component
public class SecureQueryBuilder {
    
    private static final Set<String> ALLOWED_FUNCTIONS = Set.of(
        "SUM", "COUNT", "AVG", "MIN", "MAX", "UPPER", "LOWER", "TRIM"
    );
    
    private static final Set<String> BLOCKED_KEYWORDS = Set.of(
        "DROP", "DELETE", "TRUNCATE", "ALTER", "CREATE", "INSERT", "UPDATE", 
        "EXEC", "EXECUTE", "DECLARE", "UNION", "SHUTDOWN"
    );
    
    public String buildSecureQuery(QueryDefinition definition) {
        StringBuilder sql = new StringBuilder("SELECT ");
        
        // Build SELECT clause with validation
        List<String> selectItems = new ArrayList<>();
        for (String column : definition.getSelectColumns()) {
            validateColumnName(column);
            selectItems.add(escapeIdentifier(column));
        }
        sql.append(String.join(", ", selectItems));
        
        // Build FROM clause
        sql.append(" FROM ").append(escapeIdentifier(definition.getTableName()));
        
        // Build WHERE clause with parameterized conditions
        if (!definition.getFilters().isEmpty()) {
            sql.append(" WHERE ");
            List<String> conditions = new ArrayList<>();
            for (FilterCondition filter : definition.getFilters()) {
                validateColumnName(filter.getColumn());
                conditions.add(escapeIdentifier(filter.getColumn()) + " = ?");
            }
            sql.append(String.join(" AND ", conditions));
        }
        
        return sql.toString();
    }
    
    private void validateColumnName(String column) {
        if (column == null || column.trim().isEmpty()) {
            throw new SecurityException("Column name cannot be empty");
        }
        
        // Check for SQL injection patterns
        if (BLOCKED_KEYWORDS.stream().anyMatch(keyword -> 
            column.toUpperCase().contains(keyword))) {
            throw new SecurityException("Blocked keyword in column name: " + column);
        }
        
        // Only allow alphanumeric, underscore, and dot
        if (!column.matches("^[a-zA-Z0-9_.]+$")) {
            throw new SecurityException("Invalid column name: " + column);
        }
    }
    
    private String escapeIdentifier(String identifier) {
        return "\"" + identifier.replace("\"", "\"\"") + "\"";
    }
}
```

### Cross-Site Scripting (XSS) Prevention

#### Content Security Policy

```java
@Component
public class SecurityHeadersFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // Content Security Policy
        httpResponse.setHeader("Content-Security-Policy", 
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
            "font-src 'self' https://fonts.gstatic.com; " +
            "img-src 'self' data: https:; " +
            "connect-src 'self' https://api.semantic-layer.com; " +
            "frame-ancestors 'none';"
        );
        
        // Additional security headers
        httpResponse.setHeader("X-Frame-Options", "DENY");
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
        httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        
        chain.doFilter(request, response);
    }
}
```

#### Output Encoding

```java
@Component
public class OutputEncoder {
    
    public String encodeForHTML(String input) {
        if (input == null) return null;
        return StringEscapeUtils.escapeHtml4(input);
    }
    
    public String encodeForJavaScript(String input) {
        if (input == null) return null;
        return StringEscapeUtils.escapeEcmaScript(input);
    }
    
    public String encodeForURL(String input) {
        if (input == null) return null;
        try {
            return URLEncoder.encode(input, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }
    
    public String encodeForJSON(String input) {
        if (input == null) return null;
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }
}
```

### Session Management

#### Secure Session Configuration

```java
@Configuration
@EnableWebSecurity
public class SessionSecurityConfig {
    
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
    
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .maximumSessions(1)
            .maxSessionsPreventsLogin(false)
            .sessionRegistry(sessionRegistry())
            .and()
            .sessionFixation().migrateSession()
            .invalidSessionUrl("/login?expired")
            .and()
            .rememberMe()
            .key("uniqueAndSecret")
            .tokenValiditySeconds(86400)
            .userDetailsService(userDetailsService)
            .and()
            .logout()
            .logoutUrl("/logout")
            .logoutSuccessUrl("/login?logout")
            .invalidateHttpSession(true)
            .deleteCookies("JSESSIONID", "remember-me");
    }
}
```

#### Session Timeout and Cleanup

```java
@Component
public class SessionManagementService {
    
    @Autowired
    private SessionRegistry sessionRegistry;
    
    @Scheduled(fixedRate = 300000) // Every 5 minutes
    public void cleanupExpiredSessions() {
        List<SessionInformation> expiredSessions = sessionRegistry.getAllSessions(null, true);
        
        for (SessionInformation session : expiredSessions) {
            if (session.isExpired()) {
                sessionRegistry.removeSessionInformation(session.getSessionId());
                auditService.logEvent("SESSION_EXPIRED", session.getPrincipal().toString());
            }
        }
    }
    
    public void invalidateUserSessions(String username) {
        List<SessionInformation> userSessions = sessionRegistry.getAllSessions(username, false);
        
        for (SessionInformation session : userSessions) {
            session.expireNow();
            auditService.logEvent("SESSION_INVALIDATED", username);
        }
    }
    
    @EventListener
    public void handleSecurityEvent(SecurityEvent event) {
        if (event.getType() == SecurityEventType.SUSPICIOUS_ACTIVITY) {
            // Invalidate all sessions for the user
            invalidateUserSessions(event.getUsername());
        }
    }
}
```

---

## Infrastructure Security

### Container Security

#### Secure Dockerfile

```dockerfile
# Use specific version, not latest
FROM openjdk:17-jre-slim@sha256:specific-hash

# Create non-root user
RUN groupadd -r semantic && useradd -r -g semantic semantic

# Install security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application files
COPY --chown=semantic:semantic target/semantic-layer.jar ./
COPY --chown=semantic:semantic config/ ./config/

# Remove unnecessary packages
RUN apt-get autoremove -y && \
    apt-get clean

# Switch to non-root user
USER semantic

# Set security labels
LABEL security.scan="enabled" \
      security.vendor="semantic-layer" \
      security.version="1.0"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Run application
ENTRYPOINT ["java", "-jar", "semantic-layer.jar"]
```

#### Kubernetes Security Context

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: semantic-layer
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: semantic-layer
        image: semantic-layer:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: logs-volume
          mountPath: /app/logs
      volumes:
      - name: tmp-volume
        emptyDir: {}
      - name: logs-volume
        emptyDir: {}
```

### Secrets Management

#### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: semantic-layer-secrets
  namespace: semantic-layer
type: Opaque
data:
  database-url: <base64-encoded-url>
  database-username: <base64-encoded-username>
  database-password: <base64-encoded-password>
  jwt-secret: <base64-encoded-jwt-secret>
  redis-password: <base64-encoded-redis-password>

---
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: semantic-layer
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "semantic-layer"

---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: semantic-layer-external-secret
  namespace: semantic-layer
spec:
  refreshInterval: 15s
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: semantic-layer-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-password
    remoteRef:
      key: semantic-layer/database
      property: password
```

#### HashiCorp Vault Integration

```java
@Configuration
@VaultPropertySource("secret/semantic-layer")
public class VaultConfig {
    
    @Bean
    public VaultTemplate vaultTemplate() {
        VaultEndpoint endpoint = new VaultEndpoint();
        endpoint.setHost("vault.company.com");
        endpoint.setPort(8200);
        endpoint.setScheme("https");
        
        ClientAuthentication authentication = new KubernetesAuthentication(
            KubernetesAuthenticationOptions.builder()
                .role("semantic-layer")
                .jwtSupplier(() -> {
                    try {
                        return Files.readString(Paths.get("/var/run/secrets/kubernetes.io/serviceaccount/token"));
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to read service account token", e);
                    }
                })
                .build()
        );
        
        return new VaultTemplate(endpoint, authentication);
    }
}

@Service
public class SecretManagementService {
    
    @Autowired
    private VaultTemplate vaultTemplate;
    
    public String getSecret(String path, String key) {
        VaultResponse response = vaultTemplate.read(path);
        if (response != null && response.getData() != null) {
            return (String) response.getData().get(key);
        }
        throw new RuntimeException("Secret not found: " + path + "/" + key);
    }
    
    public void rotateSecret(String path, String key, String newValue) {
        Map<String, Object> secrets = new HashMap<>();
        secrets.put(key, newValue);
        vaultTemplate.write(path, secrets);
        
        // Notify applications of secret rotation
        eventPublisher.publishEvent(new SecretRotationEvent(path, key));
    }
}
```

### System Hardening

#### Operating System Security

```bash
#!/bin/bash
# system-hardening.sh

# Update system
apt update && apt upgrade -y

# Remove unnecessary packages
apt autoremove -y
apt autoclean

# Configure automatic updates
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Configure SSH hardening
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config

# Add SSH security settings
cat >> /etc/ssh/sshd_config << EOF
Protocol 2
MaxAuthTries 3
MaxStartups 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 0
AllowUsers admin semantic
DenyUsers root
EOF

# Restart SSH
systemctl restart sshd

# Configure fail2ban
apt install -y fail2ban
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[semantic-layer]
enabled = true
filter = semantic-layer
port = 8080
logpath = /opt/semantic-layer/logs/application.log
maxretry = 5
EOF

# Start fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Configure file permissions
chmod 700 /root
chmod 755 /home
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group

# Disable unused services
systemctl disable apache2 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true
systemctl disable bluetooth 2>/dev/null || true
systemctl disable cups 2>/dev/null || true

# Configure kernel parameters
cat > /etc/sysctl.d/99-security.conf << EOF
# IP Spoofing protection
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# TCP hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
EOF

sysctl -p /etc/sysctl.d/99-security.conf

echo "System hardening completed"
```

---

## Compliance and Governance

### GDPR Compliance

#### Data Subject Rights Implementation

```java
@Service
public class GdprComplianceService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private AuditService auditService;
    
    // Right to Access (Article 15)
    public PersonalDataExport exportPersonalData(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
        
        PersonalDataExport export = new PersonalDataExport();
        export.setUserId(userId);
        export.setPersonalData(collectPersonalData(user));
        export.setQueryHistory(getQueryHistory(userId));
        export.setModelAccess(getModelAccessHistory(userId));
        export.setExportDate(Instant.now());
        
        auditService.logEvent("GDPR_DATA_EXPORT", userId, "Personal data exported");
        
        return export;
    }
    
    // Right to Rectification (Article 16)
    public void updatePersonalData(String userId, PersonalDataUpdate update) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
        
        String oldData = user.toString();
        applyPersonalDataUpdates(user, update);
        userRepository.save(user);
        
        auditService.logEvent("GDPR_DATA_RECTIFICATION", userId, 
            Map.of("old_data", oldData, "new_data", user.toString()));
    }
    
    // Right to Erasure (Article 17)
    public void erasePersonalData(String userId, ErasureRequest request) {
        validateErasureRequest(request);
        
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
        
        // Anonymize or delete personal data
        if (request.isFullErasure()) {
            anonymizeUser(user);
        } else {
            eraseSpecificData(user, request.getDataTypes());
        }
        
        userRepository.save(user);
        
        auditService.logEvent("GDPR_DATA_ERASURE", userId, 
            Map.of("erasure_type", request.getType(), "data_types", request.getDataTypes()));
    }
    
    // Right to Portability (Article 20)
    public byte[] exportDataForPortability(String userId, DataPortabilityRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
        
        PortableDataExport export = new PortableDataExport();
        export.setFormat(request.getFormat()); // JSON, XML, CSV
        export.setData(collectPortableData(user, request.getDataTypes()));
        
        auditService.logEvent("GDPR_DATA_PORTABILITY", userId, 
            Map.of("format", request.getFormat(), "data_types", request.getDataTypes()));
        
        return serializePortableData(export, request.getFormat());
    }
    
    private void anonymizeUser(User user) {
        user.setEmail("anonymized_" + user.getId() + "@deleted.local");
        user.setFirstName("Deleted");
        user.setLastName("User");
        user.setPhone(null);
        user.setAddress(null);
        user.setDeleted(true);
        user.setDeletionDate(Instant.now());
    }
}
```

#### Consent Management

```java
@Entity
@Table(name = "consent_records")
public class ConsentRecord {
    
    @Id
    private String id;
    
    @Column(nullable = false)
    private String userId;
    
    @Column(nullable = false)
    private String purpose;
    
    @Column(nullable = false)
    private String legalBasis;
    
    @Column(nullable = false)
    private boolean consentGiven;
    
    @Column(nullable = false)
    private Instant timestamp;
    
    @Column
    private String ipAddress;
    
    @Column
    private String userAgent;
    
    @Column
    private Instant withdrawalDate;
    
    @Column
    private String withdrawalReason;
}

@Service
public class ConsentManagementService {
    
    @Autowired
    private ConsentRepository consentRepository;
    
    public void recordConsent(String userId, String purpose, boolean consent, 
                             String ipAddress, String userAgent) {
        ConsentRecord record = new ConsentRecord();
        record.setId(UUID.randomUUID().toString());
        record.setUserId(userId);
        record.setPurpose(purpose);
        record.setLegalBasis("consent");
        record.setConsentGiven(consent);
        record.setTimestamp(Instant.now());
        record.setIpAddress(ipAddress);
        record.setUserAgent(userAgent);
        
        consentRepository.save(record);
    }
    
    public boolean hasValidConsent(String userId, String purpose) {
        return consentRepository.findLatestConsent(userId, purpose)
            .map(ConsentRecord::isConsentGiven)
            .orElse(false);
    }
    
    public void withdrawConsent(String userId, String purpose, String reason) {
        ConsentRecord record = consentRepository.findLatestConsent(userId, purpose)
            .orElseThrow(() -> new ConsentNotFoundException("No consent found"));
        
        record.setWithdrawalDate(Instant.now());
        record.setWithdrawalReason(reason);
        record.setConsentGiven(false);
        
        consentRepository.save(record);
    }
}
```

### SOX Compliance

#### Financial Data Controls

```java
@Component
public class SoxComplianceService {
    
    @Autowired
    private AuditService auditService;
    
    @EventListener
    public void auditFinancialDataAccess(DataAccessEvent event) {
        if (isFinancialData(event.getDataType())) {
            SoxAuditRecord record = new SoxAuditRecord();
            record.setUserId(event.getUserId());
            record.setDataType(event.getDataType());
            record.setAccessType(event.getAccessType());
            record.setTimestamp(event.getTimestamp());
            record.setBusinessJustification(event.getBusinessJustification());
            record.setApprovalStatus(validateAccess(event));
            
            auditService.recordSoxEvent(record);
            
            if (!record.getApprovalStatus().equals("APPROVED")) {
                throw new UnauthorizedAccessException("SOX: Unauthorized financial data access");
            }
        }
    }
    
    private boolean isFinancialData(String dataType) {
        Set<String> financialDataTypes = Set.of(
            "revenue", "profit", "expenses", "assets", "liabilities",
            "cash_flow", "accounts_receivable", "accounts_payable"
        );
        return financialDataTypes.contains(dataType.toLowerCase());
    }
    
    @Scheduled(cron = "0 0 6 * * MON") // Weekly SOX report
    public void generateSoxComplianceReport() {
        List<SoxAuditRecord> weeklyRecords = auditService.getSoxRecordsForLastWeek();
        
        SoxComplianceReport report = new SoxComplianceReport();
        report.setReportPeriod(getLastWeekRange());
        report.setTotalAccesses(weeklyRecords.size());
        report.setUnauthorizedAttempts(countUnauthorizedAttempts(weeklyRecords));
        report.setTopUsers(getTopUsersByAccess(weeklyRecords));
        report.setDataAccessBreakdown(getDataAccessBreakdown(weeklyRecords));
        
        reportService.distributeReport(report, "sox-compliance-team@company.com");
    }
}
```

### Data Retention Policies

```yaml
# data-retention-policies.yml
data_retention:
  policies:
    user_activity_logs:
      retention_period: "7 years"
      archive_after: "3 years"
      legal_basis: "SOX compliance"
      
    query_history:
      retention_period: "3 years"
      archive_after: "1 year"
      legal_basis: "Business operations"
      
    audit_logs:
      retention_period: "10 years"
      archive_after: "5 years"
      legal_basis: "Regulatory compliance"
      
    personal_data:
      retention_period: "As long as consent is valid"
      review_frequency: "Annual"
      legal_basis: "GDPR Article 6"
      
    financial_data:
      retention_period: "7 years"
      archive_after: "3 years"
      legal_basis: "SOX compliance"

  automated_cleanup:
    enabled: true
    schedule: "0 2 * * 0"  # Weekly on Sunday at 2 AM
    dry_run: false
    notification_email: "compliance@company.com"
```

#### Data Retention Service

```java
@Service
public class DataRetentionService {
    
    @Autowired
    private AuditRepository auditRepository;
    
    @Autowired
    private QueryHistoryRepository queryHistoryRepository;
    
    @Autowired
    private UserRepository userRepository;
    
    @Value("${data.retention.policies}")
    private Map<String, RetentionPolicy> retentionPolicies;
    
    @Scheduled(cron = "0 2 * * 0") // Weekly cleanup
    public void executeRetentionPolicies() {
        log.info("Starting data retention cleanup process");
        
        for (Map.Entry<String, RetentionPolicy> entry : retentionPolicies.entrySet()) {
            String dataType = entry.getKey();
            RetentionPolicy policy = entry.getValue();
            
            try {
                executeRetentionPolicy(dataType, policy);
            } catch (Exception e) {
                log.error("Failed to execute retention policy for {}: {}", dataType, e.getMessage());
            }
        }
        
        log.info("Data retention cleanup process completed");
    }
    
    private void executeRetentionPolicy(String dataType, RetentionPolicy policy) {
        LocalDate cutoffDate = LocalDate.now().minus(policy.getRetentionPeriod());
        LocalDate archiveDate = LocalDate.now().minus(policy.getArchivePeriod());
        
        switch (dataType) {
            case "audit_logs":
                cleanupAuditLogs(cutoffDate, archiveDate);
                break;
            case "query_history":
                cleanupQueryHistory(cutoffDate, archiveDate);
                break;
            case "user_activity_logs":
                cleanupUserActivityLogs(cutoffDate, archiveDate);
                break;
        }
        
        auditService.logEvent("DATA_RETENTION_EXECUTED", "system", 
            Map.of("data_type", dataType, "cutoff_date", cutoffDate.toString()));
    }
    
    private void cleanupAuditLogs(LocalDate cutoffDate, LocalDate archiveDate) {
        // Archive old records first
        List<AuditRecord> recordsToArchive = auditRepository.findByTimestampBetween(
            archiveDate.atStartOfDay(), cutoffDate.atStartOfDay());
        
        if (!recordsToArchive.isEmpty()) {
            archiveService.archiveAuditRecords(recordsToArchive);
            auditRepository.deleteByTimestampBefore(archiveDate.atStartOfDay());
        }
        
        // Delete very old records
        auditRepository.deleteByTimestampBefore(cutoffDate.atStartOfDay());
    }
}
```

---

## Security Monitoring and Incident Response

### Security Information and Event Management (SIEM)

#### Log Aggregation and Analysis

```yaml
# logstash-security.conf
input {
  beats {
    port => 5044
  }
  
  tcp {
    port => 5000
    codec => json
  }
}

filter {
  # Parse application logs
  if [fields][service] == "semantic-layer" {
    grok {
      match => { 
        "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{DATA:thread} %{DATA:logger} - %{GREEDYDATA:log_message}" 
      }
    }
    
    # Extract security events
    if [log_message] =~ /SECURITY|AUTH|LOGIN|LOGOUT|FAILED|UNAUTHORIZED/ {
      mutate {
        add_tag => ["security_event"]
      }
      
      # Parse authentication events
      if [log_message] =~ /LOGIN_FAILED/ {
        grok {
          match => { 
            "log_message" => "LOGIN_FAILED user=%{DATA:failed_user} ip=%{IP:source_ip} reason=%{GREEDYDATA:failure_reason}" 
          }
        }
        mutate {
          add_tag => ["auth_failure"]
        }
      }
      
      # Parse SQL injection attempts
      if [log_message] =~ /SQL_INJECTION/ {
        grok {
          match => { 
            "log_message" => "SQL_INJECTION_DETECTED user=%{DATA:user} query=%{GREEDYDATA:malicious_query}" 
          }
        }
        mutate {
          add_tag => ["sql_injection"]
          add_field => { "severity" => "high" }
        }
      }
    }
  }
  
  # Parse nginx access logs for security events
  if [fields][service] == "nginx" {
    grok {
      match => { 
        "message" => "%{COMBINEDAPACHELOG}" 
      }
    }
    
    # Detect suspicious patterns
    if [response] >= 400 {
      mutate {
        add_tag => ["http_error"]
      }
    }
    
    if [request] =~ /(\.\.\/|<script|javascript:|union\s+select|drop\s+table)/i {
      mutate {
        add_tag => ["potential_attack", "security_event"]
        add_field => { "severity" => "medium" }
      }
    }
  }
}

output {
  # Send to Elasticsearch
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "security-logs-%{+YYYY.MM.dd}"
  }
  
  # Send high-severity events to alerting system
  if "security_event" in [tags] and [severity] == "high" {
    http {
      url => "https://alertmanager:9093/api/v1/alerts"
      http_method => "post"
      format => "json"
      content_type => "application/json"
    }
  }
}
```

#### Real-time Security Monitoring

```java
@Component
public class SecurityEventMonitor {
    
    @Autowired
    private AlertingService alertingService;
    
    @Autowired
    private ThreatIntelligenceService threatIntelligenceService;
    
    @EventListener
    @Async
    public void handleAuthenticationFailure(AuthenticationFailureEvent event) {
        String ipAddress = event.getIpAddress();
        String username = event.getUsername();
        
        // Check for brute force attacks
        int failureCount = getFailureCount(ipAddress, Duration.ofMinutes(15));
        if (failureCount >= 5) {
            SecurityAlert alert = SecurityAlert.builder()
                .type("BRUTE_FORCE_ATTACK")
                .severity(Severity.HIGH)
                .source(ipAddress)
                .description("Multiple authentication failures detected")
                .metadata(Map.of(
                    "failure_count", failureCount,
                    "username", username,
                    "time_window", "15 minutes"
                ))
                .build();
            
            alertingService.sendAlert(alert);
            
            // Automatically block IP
            firewallService.blockIpAddress(ipAddress, Duration.ofHours(1));
        }
        
        // Check against threat intelligence
        if (threatIntelligenceService.isKnownBadIp(ipAddress)) {
            SecurityAlert alert = SecurityAlert.builder()
                .type("KNOWN_MALICIOUS_IP")
                .severity(Severity.CRITICAL)
                .source(ipAddress)
                .description("Authentication attempt from known malicious IP")
                .build();
            
            alertingService.sendAlert(alert);
            firewallService.blockIpAddress(ipAddress, Duration.ofDays(1));
        }
    }
    
    @EventListener
    @Async
    public void handleSqlInjectionAttempt(SqlInjectionEvent event) {
        SecurityAlert alert = SecurityAlert.builder()
            .type("SQL_INJECTION_ATTEMPT")
            .severity(Severity.HIGH)
            .source(event.getIpAddress())
            .description("SQL injection attempt detected")
            .metadata(Map.of(
                "user", event.getUsername(),
                "query", event.getMaliciousQuery(),
                "blocked", true
            ))
            .build();
        
        alertingService.sendAlert(alert);
        
        // Temporarily block user and IP
        userService.temporarilyBlockUser(event.getUsername(), Duration.ofMinutes(30));
        firewallService.blockIpAddress(event.getIpAddress(), Duration.ofHours(2));
    }
    
    @EventListener
    @Async
    public void handleUnusualDataAccess(DataAccessEvent event) {
        // Check for unusual access patterns
        if (isUnusualAccessPattern(event)) {
            SecurityAlert alert = SecurityAlert.builder()
                .type("UNUSUAL_DATA_ACCESS")
                .severity(Severity.MEDIUM)
                .source(event.getIpAddress())
                .description("Unusual data access pattern detected")
                .metadata(Map.of(
                    "user", event.getUsername(),
                    "data_volume", event.getRecordCount(),
                    "access_time", event.getTimestamp().toString()
                ))
                .build();
            
            alertingService.sendAlert(alert);
        }
    }
    
    private boolean isUnusualAccessPattern(DataAccessEvent event) {
        // Check for large data exports
        if (event.getRecordCount() > 100000) {
            return true;
        }
        
        // Check for access outside business hours
        LocalTime accessTime = event.getTimestamp().toLocalTime();
        if (accessTime.isBefore(LocalTime.of(7, 0)) || accessTime.isAfter(LocalTime.of(19, 0))) {
            return true;
        }
        
        // Check for unusual geographic location
        String userLocation = geoLocationService.getLocation(event.getIpAddress());
        String expectedLocation = userService.getUserLocation(event.getUsername());
        if (!userLocation.equals(expectedLocation)) {
            return true;
        }
        
        return false;
    }
}
```

### Incident Response Plan

#### Automated Incident Response

```java
@Service
public class IncidentResponseService {
    
    @Autowired
    private NotificationService notificationService;
    
    @Autowired
    private FirewallService firewallService;
    
    @Autowired
    private UserService userService;
    
    @EventListener
    public void handleSecurityIncident(SecurityIncident incident) {
        log.error("Security incident detected: {}", incident);
        
        // Immediate containment actions
        containThreat(incident);
        
        // Notify security team
        notifySecurityTeam(incident);
        
        // Start investigation
        startInvestigation(incident);
        
        // Document incident
        documentIncident(incident);
    }
    
    private void containThreat(SecurityIncident incident) {
        switch (incident.getType()) {
            case "BRUTE_FORCE_ATTACK":
            case "SQL_INJECTION_ATTEMPT":
                // Block source IP
                firewallService.blockIpAddress(incident.getSourceIp(), Duration.ofHours(24));
                
                // If user account is involved, temporarily disable it
                if (incident.getUsername() != null) {
                    userService.temporarilyDisableUser(incident.getUsername());
                }
                break;
                
            case "DATA_BREACH":
                // Immediately revoke all sessions for affected users
                incident.getAffectedUsers().forEach(userService::revokeAllSessions);
                
                // Disable affected data sources temporarily
                incident.getAffectedDataSources().forEach(dataSourceService::disable);
                break;
                
            case "PRIVILEGE_ESCALATION":
                // Revoke elevated privileges
                userService.revokeElevatedPrivileges(incident.getUsername());
                
                // Force password reset
                userService.forcePasswordReset(incident.getUsername());
                break;
        }
    }
    
    private void notifySecurityTeam(SecurityIncident incident) {
        SecurityAlert alert = SecurityAlert.builder()
            .type("SECURITY_INCIDENT")
            .severity(incident.getSeverity())
            .title("Security Incident: " + incident.getType())
            .description(incident.getDescription())
            .affectedSystems(incident.getAffectedSystems())
            .containmentActions(incident.getContainmentActions())
            .build();
        
        // Send immediate notification
        notificationService.sendPagerDutyAlert(alert);
        notificationService.sendSlackAlert(alert);
        notificationService.sendEmailAlert(alert, "security-team@company.com");
        
        // For critical incidents, also notify executives
        if (incident.getSeverity() == Severity.CRITICAL) {
            notificationService.sendEmailAlert(alert, "executives@company.com");
        }
    }
    
    @Async
    private void startInvestigation(SecurityIncident incident) {
        Investigation investigation = Investigation.builder()
            .incidentId(incident.getId())
            .startTime(Instant.now())
            .investigator("automated-system")
            .status(InvestigationStatus.IN_PROGRESS)
            .build();
        
        // Collect relevant logs
        List<LogEntry> relevantLogs = logService.getLogsForTimeRange(
            incident.getTimestamp().minus(Duration.ofHours(2)),
            incident.getTimestamp().plus(Duration.ofMinutes(30))
        );
        
        investigation.setLogs(relevantLogs);
        
        // Analyze network traffic
        if (incident.getSourceIp() != null) {
            NetworkTrafficAnalysis trafficAnalysis = networkAnalysisService
                .analyzeTraffic(incident.getSourceIp(), Duration.ofHours(24));
            investigation.setNetworkAnalysis(trafficAnalysis);
        }
        
        // Check for IOCs (Indicators of Compromise)
        List<String> iocs = threatIntelligenceService.checkForIOCs(incident);
        investigation.setIndicatorsOfCompromise(iocs);
        
        investigationRepository.save(investigation);
    }
}
```

#### Manual Response Procedures

```markdown
# Security Incident Response Playbook

## Incident Classification

### Severity Levels
- **Critical**: Data breach, system compromise, service unavailable
- **High**: Attempted breach, privilege escalation, data access violation
- **Medium**: Suspicious activity, policy violation, failed security controls
- **Low**: Minor security events, user errors

### Response Times
- **Critical**: 15 minutes
- **High**: 1 hour
- **Medium**: 4 hours
- **Low**: 24 hours

## Response Procedures

### Step 1: Initial Assessment (0-15 minutes)
1. Confirm the incident is genuine
2. Classify severity level
3. Activate incident response team
4. Begin containment if necessary

### Step 2: Containment (15-60 minutes)
1. Isolate affected systems
2. Block malicious IP addresses
3. Disable compromised accounts
4. Preserve evidence

### Step 3: Investigation (1-24 hours)
1. Analyze logs and system activity
2. Determine scope of compromise
3. Identify attack vectors
4. Document findings

### Step 4: Eradication (Variable)
1. Remove malware or unauthorized access
2. Close security vulnerabilities
3. Update security controls
4. Patch affected systems

### Step 5: Recovery (Variable)
1. Restore systems from clean backups
2. Monitor for continued activity
3. Gradually restore services
4. Validate security controls

### Step 6: Lessons Learned (1-2 weeks post-incident)
1. Conduct post-incident review
2. Update security procedures
3. Improve monitoring and detection
4. Train staff on new procedures
```

### Threat Intelligence Integration

```java
@Service
public class ThreatIntelligenceService {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Value("${threat.intelligence.api.key}")
    private String apiKey;
    
    @Cacheable(value = "threat-intel", key = "#ipAddress")
    public ThreatIntelligence getIpReputation(String ipAddress) {
        String url = "https://api.threatintel.com/v1/ip/" + ipAddress;
        
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + apiKey);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        try {
            ResponseEntity<ThreatIntelResponse> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, ThreatIntelResponse.class);
            
            return mapToThreatIntelligence(response.getBody());
        } catch (Exception e) {
            log.warn("Failed to get threat intelligence for IP {}: {}", ipAddress, e.getMessage());
            return ThreatIntelligence.unknown();
        }
    }
    
    public boolean isKnownBadIp(String ipAddress) {
        ThreatIntelligence intel = getIpReputation(ipAddress);
        return intel.getRiskScore() > 70 || intel.isMalicious();
    }
    
    public List<String> checkForIOCs(SecurityIncident incident) {
        List<String> iocs = new ArrayList<>();
        
        // Check IP addresses
        if (incident.getSourceIp() != null) {
            ThreatIntelligence intel = getIpReputation(incident.getSourceIp());
            if (intel.isMalicious()) {
                iocs.add("Malicious IP: " + incident.getSourceIp());
            }
        }
        
        // Check file hashes (if applicable)
        if (incident.getFileHashes() != null) {
            for (String hash : incident.getFileHashes()) {
                if (isKnownMaliciousHash(hash)) {
                    iocs.add("Malicious file hash: " + hash);
                }
            }
        }
        
        // Check domain names
        if (incident.getDomains() != null) {
            for (String domain : incident.getDomains()) {
                if (isKnownMaliciousDomain(domain)) {
                    iocs.add("Malicious domain: " + domain);
                }
            }
        }
        
        return iocs;
    }
    
    @Scheduled(fixedRate = 3600000) // Update every hour
    public void updateThreatFeeds() {
        try {
            // Download latest threat feeds
            List<ThreatIndicator> indicators = downloadThreatFeeds();
            
            // Update local threat database
            threatIndicatorRepository.deleteAll();
            threatIndicatorRepository.saveAll(indicators);
            
            log.info("Updated threat intelligence feeds with {} indicators", indicators.size());
        } catch (Exception e) {
            log.error("Failed to update threat intelligence feeds: {}", e.getMessage());
        }
    }
}
```

---

## Security Best Practices

### Development Security Guidelines

#### Secure Coding Standards

```java
// Example: Secure coding practices

@RestController
@Validated
public class SecureController {
    
    // Input validation
    @PostMapping("/api/v1/queries")
    public ResponseEntity<QueryResult> executeQuery(
            @Valid @RequestBody QueryRequest request,
            @RequestHeader("Authorization") String authHeader,
            HttpServletRequest httpRequest) {
        
        // 1. Authenticate and authorize user
        User user = authenticationService.authenticate(authHeader);
        authorizationService.checkPermission(user, "query:execute");
        
        // 2. Validate and sanitize input
        validateQueryRequest(request);
        sanitizeQueryRequest(request);
        
        // 3. Apply security controls
        applySecurityFilters(request, user);
        
        // 4. Execute with monitoring
        QueryResult result = queryService.execute(request);
        
        // 5. Audit the operation
        auditService.logQueryExecution(user.getId(), request, result);
        
        // 6. Sanitize output
        sanitizeQueryResult(result);
        
        return ResponseEntity.ok(result);
    }
    
    private void validateQueryRequest(QueryRequest request) {
        // Check for SQL injection patterns
        if (containsSqlInjection(request.getQuery())) {
            throw new SecurityException("SQL injection detected");
        }
        
        // Validate field names against whitelist
        for (String field : request.getSelectFields()) {
            if (!isValidFieldName(field)) {
                throw new ValidationException("Invalid field name: " + field);
            }
        }
        
        // Check query complexity
        if (isComplexQuery(request)) {
            throw new ValidationException("Query too complex");
        }
    }
    
    private void applySecurityFilters(QueryRequest request, User user) {
        // Apply row-level security
        List<Filter> securityFilters = securityService.getSecurityFilters(user);
        request.getFilters().addAll(securityFilters);
        
        // Apply column-level security
        List<String> allowedColumns = securityService.getAllowedColumns(user, request.getTable());
        request.getSelectFields().retainAll(allowedColumns);
    }
}
```

#### Security Testing Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run SAST with SonarQube
      uses: sonarqube-quality-gate-action@master
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
    
    - name: Run dependency check
      run: |
        mvn org.owasp:dependency-check-maven:check
        
    - name: Run container security scan
      run: |
        docker build -t semantic-layer:test .
        trivy image semantic-layer:test
        
    - name: Run secrets scan
      uses: trufflesecurity/trufflehog@main
      with:
        path: ./
        base: main
        head: HEAD
```

### Deployment Security Checklist

#### Pre-Deployment Security Verification

```bash
#!/bin/bash
# pre-deployment-security-check.sh

echo "Starting pre-deployment security verification..."

# 1. Verify all secrets are properly configured
echo "Checking secrets configuration..."
kubectl get secrets -n semantic-layer | grep -q "semantic-layer-secrets" || {
    echo "ERROR: Secrets not found"
    exit 1
}

# 2. Check TLS certificates
echo "Verifying TLS certificates..."
openssl x509 -in /etc/ssl/certs/semantic-layer.crt -text -noout | grep -q "Not After" || {
    echo "ERROR: Invalid TLS certificate"
    exit 1
}

# 3. Verify security contexts
echo "Checking security contexts..."
kubectl get deployment semantic-layer -o jsonpath='{.spec.template.spec.securityContext.runAsNonRoot}' | grep -q "true" || {
    echo "ERROR: Container not running as non-root"
    exit 1
}

# 4. Check network policies
echo "Verifying network policies..."
kubectl get networkpolicy -n semantic-layer | grep -q "semantic-layer-policy" || {
    echo "ERROR: Network policy not found"
    exit 1
}

# 5. Verify RBAC configuration
echo "Checking RBAC..."
kubectl auth can-i --list --as=system:serviceaccount:semantic-layer:default | grep -q "get.*pods" || {
    echo "ERROR: Incorrect RBAC configuration"
    exit 1
}

# 6. Check resource limits
echo "Verifying resource limits..."
kubectl get deployment semantic-layer -o jsonpath='{.spec.template.spec.containers[0].resources.limits}' | grep -q "memory" || {
    echo "ERROR: No resource limits configured"
    exit 1
}

# 7. Verify security scanning results
echo "Checking security scan results..."
[ -f "security-scan-results.json" ] && jq '.vulnerabilities | length' security-scan-results.json | awk '$1 > 0 {exit 1}' || {
    echo "ERROR: Security vulnerabilities found"
    exit 1
}

echo "Pre-deployment security verification completed successfully"
```

### Security Metrics and KPIs

#### Security Dashboard Configuration

```yaml
# grafana-security-dashboard.json
{
  "dashboard": {
    "title": "Security Metrics Dashboard",
    "panels": [
      {
        "title": "Authentication Events",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(auth_attempts_total[5m])",
            "legendFormat": "Auth Attempts/sec"
          },
          {
            "expr": "rate(auth_failures_total[5m])",
            "legendFormat": "Auth Failures/sec"
          }
        ]
      },
      {
        "title": "Security Alerts",
        "type": "graph",
        "targets": [
          {
            "expr": "increase(security_alerts_total[1h])",
            "legendFormat": "{{severity}} alerts"
          }
        ]
      },
      {
        "title": "Failed Login Attempts by IP",
        "type": "table",
        "targets": [
          {
            "expr": "topk(10, sum by (source_ip) (increase(auth_failures_total[24h])))",
            "format": "table"
          }
        ]
      },
      {
        "title": "Data Access Violations",
        "type": "graph",
        "targets": [
          {
            "expr": "increase(data_access_violations_total[1h])",
            "legendFormat": "{{violation_type}}"
          }
        ]
      }
    ]
  }
}
```

#### Security Metrics Collection

```java
@Component
public class SecurityMetricsCollector {
    
    private final MeterRegistry meterRegistry;
    private final Counter authAttempts;
    private final Counter authFailures;
    private final Counter securityAlerts;
    private final Counter dataAccessViolations;
    
    public SecurityMetricsCollector(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.authAttempts = Counter.builder("auth_attempts_total")
            .description("Total authentication attempts")
            .register(meterRegistry);
        this.authFailures = Counter.builder("auth_failures_total")
            .description("Total authentication failures")
            .tag("source_ip", "unknown")
            .register(meterRegistry);
        this.securityAlerts = Counter.builder("security_alerts_total")
            .description("Total security alerts")
            .tag("severity", "unknown")
            .register(meterRegistry);
        this.dataAccessViolations = Counter.builder("data_access_violations_total")
            .description("Total data access violations")
            .tag("violation_type", "unknown")
            .register(meterRegistry);
    }
    
    @EventListener
    public void recordAuthenticationAttempt(AuthenticationEvent event) {
        authAttempts.increment(
            Tags.of(
                "method", event.getMethod(),
                "source_ip", event.getSourceIp()
            )
        );
        
        if (!event.isSuccessful()) {
            authFailures.increment(
                Tags.of(
                    "source_ip", event.getSourceIp(),
                    "reason", event.getFailureReason()
                )
            );
        }
    }
    
    @EventListener
    public void recordSecurityAlert(SecurityAlert alert) {
        securityAlerts.increment(
            Tags.of(
                "severity", alert.getSeverity().toString(),
                "type", alert.getType()
            )
        );
    }
    
    @EventListener
    public void recordDataAccessViolation(DataAccessViolationEvent event) {
        dataAccessViolations.increment(
            Tags.of(
                "violation_type", event.getViolationType(),
                "user_id", event.getUserId()
            )
        );
    }
}
```
