# Contributing to Universal Semantic Layer

First off, thank you for considering contributing to the Universal Semantic Layer project! It's people like you that make this project such a great tool for democratizing data access across organizations.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Workflow](#development-workflow)
- [Style Guidelines](#style-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [conduct@semantic-layer.org](mailto:conduct@semantic-layer.org).

## Getting Started

Before you begin:
- Have you read the [README](README.md)?
- Have you reviewed the [architecture documentation](docs/architecture.md)?
- Check if your issue/idea has already been reported in [Issues](https://github.com/your-org/universal-semantic-layer/issues)
- Check if your idea is being worked on in [Pull Requests](https://github.com/your-org/universal-semantic-layer/pulls)

## Development Setup

### Prerequisites

We use WSL2 with Ubuntu for development. Please ensure you have:

- Windows 10/11 with WSL2 enabled
- Ubuntu 20.04 or 22.04 on WSL2
- Docker Desktop with WSL2 backend
- Cursor IDE (or VS Code with WSL extension)
- Git configured in WSL2

### Setting Up Your Development Environment

1. **Fork and Clone the Repository**
   ```bash
   # Fork the repo on GitHub first, then:
   git clone https://github.com/YOUR_USERNAME/universal-semantic-layer.git
   cd universal-semantic-layer
   git remote add upstream https://github.com/your-org/universal-semantic-layer.git
   ```

2. **Run the Setup Script**
   ```bash
   ./scripts/setup-dev-env.sh
   ```
   This script will:
   - Install all required dependencies
   - Set up Docker services (PostgreSQL, Redis, Keycloak, Kong)
   - Configure your local environment
   - Initialize the database

3. **Verify Your Setup**
   ```bash
   # Check all services are running
   docker-compose ps
   
   # Run the test suite
   ./scripts/run-tests.sh
   ```

4. **Open in Cursor**
   ```bash
   cursor .
   ```

For detailed setup instructions, see [local-dev-setup.md](docs/local-dev-setup.md).

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce**
- **Provide specific examples**
- **Describe the behavior you observed and expected**
- **Include screenshots if applicable**
- **Include system information**:
  - OS version
  - Docker version
  - Node.js version
  - Java version

Use the bug report template when creating an issue.

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description of the suggested enhancement**
- **Provide specific use cases**
- **Explain why this enhancement would be useful**
- **List any alternatives you've considered**

### Your First Code Contribution

Unsure where to begin? Look for these labels:

- `good first issue` - Good for newcomers
- `help wanted` - Extra attention is needed
- `documentation` - Help improve our docs
- `testing` - Help improve test coverage

### Areas We Need Help

1. **Backend Development** (Java/Spring Boot)
   - Query optimization
   - New data source connectors
   - Performance improvements
   - Security enhancements

2. **Frontend Development** (React/TypeScript)
   - UI/UX improvements
   - New visualization components
   - Mobile responsiveness
   - Accessibility features

3. **DevOps/Infrastructure**
   - Kubernetes optimizations
   - CI/CD improvements
   - Monitoring and alerting
   - Cloud deployment templates

4. **Documentation**
   - User guides
   - API documentation
   - Tutorial videos
   - Translation

## Development Workflow

### Branch Naming Convention

- `feature/` - New features (e.g., `feature/add-snowflake-connector`)
- `bugfix/` - Bug fixes (e.g., `bugfix/query-timeout-issue`)
- `hotfix/` - Urgent fixes for production (e.g., `hotfix/security-patch`)
- `docs/` - Documentation updates (e.g., `docs/update-api-guide`)
- `test/` - Test additions or fixes (e.g., `test/add-integration-tests`)
- `refactor/` - Code refactoring (e.g., `refactor/optimize-query-engine`)

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions or modifications
- `chore`: Build process or auxiliary tool changes
- `perf`: Performance improvements

**Examples:**
```
feat(query): add support for window functions

Added OVER clause support to the query builder, enabling
window functions like ROW_NUMBER(), RANK(), and LAG().

Closes #123
```

```
fix(auth): resolve token refresh race condition

Multiple concurrent requests could cause token refresh to fail.
Added mutex to ensure only one refresh occurs at a time.

Fixes #456
```

### Development Process

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Write clean, readable code
   - Follow our style guidelines
   - Add/update tests
   - Update documentation

3. **Test Your Changes**
   ```bash
   # Run backend tests
   cd backend
   ./mvnw test
   
   # Run frontend tests
   cd frontend
   npm test
   
   # Run integration tests
   docker-compose -f docker-compose.test.yml up --abort-on-container-exit
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat(component): add amazing feature"
   ```

5. **Keep Your Fork Updated**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

6. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**

## Style Guidelines

### Java/Spring Boot

We use Google Java Style Guide with some modifications:

```java
// Good example
@Service
@Slf4j
public class QueryExecutionService {
    
    private static final int DEFAULT_TIMEOUT = 30;
    
    private final QueryEngine queryEngine;
    private final CacheService cacheService;
    
    @Autowired
    public QueryExecutionService(
            QueryEngine queryEngine,
            CacheService cacheService) {
        this.queryEngine = queryEngine;
        this.cacheService = cacheService;
    }
    
    public QueryResult executeQuery(QueryRequest request) {
        log.debug("Executing query: {}", request.getQueryId());
        
        // Check cache first
        Optional<QueryResult> cachedResult = cacheService
                .get(request.getCacheKey());
        if (cachedResult.isPresent()) {
            return cachedResult.get();
        }
        
        // Execute query
        QueryResult result = queryEngine.execute(request);
        cacheService.put(request.getCacheKey(), result);
        
        return result;
    }
}
```

**Key Points:**
- Use constructor injection
- Add proper logging
- Handle null cases with Optional
- Use meaningful variable names
- Add JavaDoc for public methods

### React/TypeScript

We follow Airbnb React Style Guide with TypeScript:

```typescript
// Good example
import React, { useState, useCallback } from 'react';
import { useDispatch } from 'react-redux';
import { Button, Card } from '@mui/material';
import { QueryResult } from '../../types';
import { executeQuery } from '../../store/querySlice';

interface QueryBuilderProps {
  modelId: string;
  onQueryComplete?: (result: QueryResult) => void;
}

export const QueryBuilder: React.FC<QueryBuilderProps> = ({
  modelId,
  onQueryComplete,
}) => {
  const dispatch = useDispatch();
  const [isLoading, setIsLoading] = useState(false);
  
  const handleExecuteQuery = useCallback(async () => {
    setIsLoading(true);
    try {
      const result = await dispatch(executeQuery({ modelId })).unwrap();
      onQueryComplete?.(result);
    } catch (error) {
      console.error('Query execution failed:', error);
    } finally {
      setIsLoading(false);
    }
  }, [dispatch, modelId, onQueryComplete]);
  
  return (
    <Card>
      <Button
        variant="contained"
        onClick={handleExecuteQuery}
        disabled={isLoading}
      >
        {isLoading ? 'Executing...' : 'Execute Query'}
      </Button>
    </Card>
  );
};
```

**Key Points:**
- Use functional components with hooks
- Define proper TypeScript interfaces
- Handle loading and error states
- Use proper event handlers
- Memoize callbacks with useCallback

### General Guidelines

- **No commented-out code** - Use version control instead
- **No console.log in production code** - Use proper logging
- **Meaningful names** - Variables and functions should be self-documenting
- **Keep functions small** - Each function should do one thing well
- **DRY principle** - Don't Repeat Yourself
- **SOLID principles** - Follow object-oriented design principles

## Testing Guidelines

### Test Coverage Requirements

- **Backend**: Minimum 80% code coverage
- **Frontend**: Minimum 70% code coverage
- **Critical paths**: 100% coverage for authentication, authorization, and data access

### Backend Testing

```java
@SpringBootTest
@AutoConfigureMockMvc
class QueryControllerTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @MockBean
    private QueryService queryService;
    
    @Test
    @WithMockUser(roles = "ANALYST")
    void executeQuery_WithValidRequest_ShouldReturnResults() throws Exception {
        // Given
        QueryRequest request = QueryRequest.builder()
                .modelId("test-model")
                .query("SELECT * FROM customers")
                .build();
                
        QueryResult expectedResult = QueryResult.builder()
                .rows(List.of(Map.of("id", 1, "name", "Test")))
                .build();
                
        when(queryService.execute(any())).thenReturn(expectedResult);
        
        // When & Then
        mockMvc.perform(post("/api/v1/queries")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rows[0].name").value("Test"));
    }
}
```

### Frontend Testing

```typescript
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { QueryBuilder } from '../QueryBuilder';
import { store } from '../../store';

describe('QueryBuilder', () => {
  it('should execute query when button is clicked', async () => {
    // Arrange
    const onQueryComplete = jest.fn();
    render(
      <Provider store={store}>
        <QueryBuilder 
          modelId="test-model" 
          onQueryComplete={onQueryComplete}
        />
      </Provider>
    );
    
    // Act
    const executeButton = screen.getByText('Execute Query');
    fireEvent.click(executeButton);
    
    // Assert
    await waitFor(() => {
      expect(screen.getByText('Executing...')).toBeInTheDocument();
    });
  });
});
```

### Integration Testing

```yaml
# docker-compose.test.yml
version: '3.8'

services:
  test-runner:
    build:
      context: .
      dockerfile: Dockerfile.test
    environment:
      - TEST_ENV=integration
    depends_on:
      - postgres-test
      - redis-test
      - keycloak-test
    command: npm run test:integration
```

## Documentation

### Code Documentation

**Java:**
```java
/**
 * Executes a semantic query against the specified model.
 * 
 * @param request The query request containing model ID and query parameters
 * @return QueryResult containing the execution results
 * @throws QueryExecutionException if the query fails to execute
 * @throws SecurityException if the user lacks necessary permissions
 */
public QueryResult executeQuery(QueryRequest request) {
    // Implementation
}
```

**TypeScript:**
```typescript
/**
 * Custom hook for managing query execution state.
 * 
 * @param modelId - The ID of the semantic model to query
 * @returns Object containing query state and execution function
 * 
 * @example
 * const { data, loading, error, execute } = useQuery('model-123');
 */
export function useQuery(modelId: string) {
  // Implementation
}
```

### API Documentation

All REST endpoints must include OpenAPI annotations:

```java
@Operation(
    summary = "Execute a semantic query",
    description = "Executes a query against the specified semantic model"
)
@ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "Query executed successfully",
        content = @Content(schema = @Schema(implementation = QueryResult.class))
    ),
    @ApiResponse(
        responseCode = "400",
        description = "Invalid query syntax"
    ),
    @ApiResponse(
        responseCode = "403",
        description = "Insufficient permissions"
    )
})
@PostMapping("/queries")
public ResponseEntity<QueryResult> executeQuery(@RequestBody QueryRequest request) {
    // Implementation
}
```

## Pull Request Process

1. **Before Creating a PR:**
   - Ensure all tests pass
   - Update documentation
   - Run linters and fix any issues
   - Rebase on latest main branch

2. **PR Title Format:**
   Follow the same convention as commit messages:
   ```
   feat(query): add support for window functions
   ```

3. **PR Description Template:**
   ```markdown
   ## Description
   Brief description of what this PR does.
   
   ## Type of Change
   - [ ] Bug fix (non-breaking change)
   - [ ] New feature (non-breaking change)
   - [ ] Breaking change
   - [ ] Documentation update
   
   ## How Has This Been Tested?
   - [ ] Unit tests
   - [ ] Integration tests
   - [ ] Manual testing
   
   ## Checklist
   - [ ] My code follows the style guidelines
   - [ ] I have performed a self-review
   - [ ] I have commented my code where necessary
   - [ ] I have updated the documentation
   - [ ] My changes generate no new warnings
   - [ ] I have added tests that prove my fix/feature works
   - [ ] New and existing unit tests pass locally
   - [ ] Any dependent changes have been merged
   
   ## Screenshots (if applicable)
   
   ## Related Issues
   Closes #123
   ```

4. **Review Process:**
   - At least 2 approvals required for merge
   - All CI checks must pass
   - No merge conflicts
   - PR author should not merge their own PR

5. **After PR is Merged:**
   - Delete your feature branch
   - Update your local main branch
   - Close related issues

## Community

### Communication Channels

- **GitHub Discussions**: For general questions and discussions
- **Slack**: [Join our Slack](https://semantic-layer.slack.com)
- **Twitter**: [@SemanticLayer](https://twitter.com/SemanticLayer)
- **Blog**: [blog.semantic-layer.org](https://blog.semantic-layer.org)

### Getting Help

- Check the [documentation](docs/)
- Search [existing issues](https://github.com/your-org/universal-semantic-layer/issues)
- Ask in [GitHub Discussions](https://github.com/your-org/universal-semantic-layer/discussions)
- Join our [Slack community](https://semantic-layer.slack.com)

### Recognition

Contributors who make significant contributions will be:
- Added to our [Contributors](CONTRIBUTORS.md) file
- Mentioned in release notes
- Invited to join our Contributors team on GitHub
- Eligible for project swag and conference tickets

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

## Questions?

Feel free to contact the project maintainers at [maintainers@semantic-layer.org](mailto:maintainers@semantic-layer.org).

Thank you for contributing to the Universal Semantic Layer project! 🎉
