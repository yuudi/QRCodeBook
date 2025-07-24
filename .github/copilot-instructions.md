# AI Coding Agent Instructions for QRCodeBook

This document provides specific coding guidelines and architectural patterns for AI coding agents working on the QRCodeBook project.

## Project Overview

QRCodeBook is a Go-based web application built with Gin framework, GORM ORM, and PostgreSQL database. It features dual authentication (JWT + WebAuthn), note management with versioning, and follows a clean architecture pattern.

## Architecture Patterns

### Database Layer (`src/internal/model/`)
- **Global Database Pattern**: Use `model.DB` (global GORM instance) for all database operations
- **Model Definition**: GORM models with proper tags and relationships
- **Migration**: Auto-migrate tables in `database.go` using `db.AutoMigrate()`
- **UUID Primary Keys**: Use `datatypes.BinUUID` for all primary keys
- **Compound Keys**: For versioning systems, use compound primary keys like `gorm:"primaryKey"`

**Example Model Pattern:**
```go
type ModelName struct {
    ID           datatypes.BinUUID `gorm:"primaryKey" json:"id"`
    // Other fields with proper GORM tags
}

// Model methods for CRUD operations
func GetModelByID(id string) (*ModelName, error) {
    var model ModelName
    result := DB.First(&model, "id = ?", id)
    return &model, result.Error
}
```

### Controller Layer (`src/internal/controller/`)
- **Function-Based Controllers**: Use standalone functions, NOT struct-based controllers
- **Request Binding**: Use `c.ShouldBindJSON(&req)` for JSON input validation
- **User Context**: Extract user from JWT using `c.Get("user").(model.UserJWTContent)`
- **Error Handling**: Return appropriate HTTP status codes with descriptive error messages
- **Cookie Management**: Use `c.SetCookie()` for session management

**Example Controller Pattern:**
```go
func ControllerName(c *gin.Context) {
    var req RequestStruct
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // Business logic here
    
    c.JSON(http.StatusOK, gin.H{"data": result})
}
```

### Router Layer (`src/internal/router/`)
- **Clean Separation**: Router only handles route registration, NO business logic
- **Middleware Application**: Apply middleware to route groups using `.Use()`
- **API Versioning**: Use `/api/v0` prefix for all API routes
- **Authentication**: Use `middleware.LoginRequired()` for protected routes

**Example Router Pattern:**
```go
func SetupRouter() *gin.Engine {
    r := gin.Default()
    
    api := r.Group("/api/v0")
    
    // Protected routes
    protected := api.Group("/resource")
    protected.Use(middleware.LoginRequired())
    protected.GET("/", controller.GetResource)
    
    return r
}
```

### Middleware Layer (`src/internal/middleware/`)
- **Authentication**: `LoginRequired()` extracts JWT from cookies and sets user context
- **Caching**: Use `PublicCache()`, `PrivateCache()`, or `NoCache()` middleware
- **Error Handling**: Middleware should call `c.Abort()` on authentication failures

## Security Patterns

### JWT and Encryption
- **Encrypted JWT**: Use `utils.GenerateEncryptedJWT()` and `utils.ParseEncryptedJWT()` for sensitive data
- **Standard JWT**: Use `utils.GenerateJWT()` and `utils.ParseJWT()` for simple values
- **Session Cookies**: Set secure, httpOnly cookies with proper expiration times
- **Token Validation**: Always validate JWT tokens in middleware before accessing protected resources

### WebAuthn Integration
- **Session Management**: Store WebAuthn sessions in encrypted JWT cookies
- **Database Transactions**: Use database transactions for WebAuthn credential storage
- **User Interface**: Implement WebAuthn interface methods on User model

## Database Patterns

### Connection and Configuration
- **Environment Variables**: Use `utils.MustGetEnv()` for required configuration
- **Global Instance**: Initialize `model.DB` once in `model.InitDB()`
- **PostgreSQL Specific**: Use PostgreSQL-specific features and constraints

### CRUD Operations
- **Pagination**: Include offset and limit parameters for list operations
- **Soft Deletes**: Use GORM's soft delete feature where appropriate
- **Preloading**: Use `Preload()` for loading related data
- **Error Handling**: Check for `gorm.ErrRecordNotFound` specifically

**Example CRUD Pattern:**
```go
func GetUserItems(userID string, offset, limit int) ([]Item, error) {
    var items []Item
    result := DB.Where("user_id = ?", userID).
        Offset(offset).
        Limit(limit).
        Find(&items)
    return items, result.Error
}
```

## Testing Patterns

### Test Structure
- **Test Files**: Use `*_test.go` suffix for test files
- **Test Setup**: Use test-specific database setup or mocking
- **Crypto Testing**: Use `utils.SetTestKey()` for consistent test encryption keys

## Configuration Management

### Environment Variables
- **Required Variables**: Use `utils.MustGetEnv()` for required configuration
- **Initialization Order**: Follow the pattern: `config.Init()` → `utils.InitKey()` → `utils.InitWebAuthn()` → `model.InitDB()`

## Error Handling Guidelines

### HTTP Error Responses
- **400 Bad Request**: Invalid input, validation errors
- **401 Unauthorized**: Authentication failures
- **403 Forbidden**: Authorization failures  
- **404 Not Found**: Resource not found
- **409 Conflict**: Duplicate resources
- **500 Internal Server Error**: Server-side errors

### Database Error Handling
- **Record Not Found**: Return 404 for `gorm.ErrRecordNotFound`
- **Constraint Violations**: Return 409 for unique constraint violations
- **Transaction Rollback**: Always handle transaction rollbacks in defer functions

## Code Organization

### Import Order
1. Standard library imports
2. Third-party imports  
3. Local project imports

### File Naming
- **Controllers**: `{feature}.go` (e.g., `login-password.go`, `note.go`)
- **Models**: `{entity}.go` (e.g., `user.go`, `note.go`)
- **Tests**: `{feature}_test.go`

## Development Workflow

### Building and Running
- **Build Command**: `go build -o bin/qrcodebook`
- **Development**: Use Docker Compose for local development
- **Testing**: Run `go test ./...` for all tests

### Git Workflow
- **Branch Protection**: Main branch requires PR reviews
- **CI/CD**: GitHub Actions run tests on Go file changes
- **Test Coverage**: Maintain test coverage for critical functions

## Common Patterns to Follow

1. **Always validate input lengths** and formats in controllers
2. **Use transactions** for multi-table operations
3. **Set appropriate cache headers** using middleware
4. **Extract user context** from JWT in protected endpoints
5. **Return consistent JSON responses** with proper error messages
6. **Use compound primary keys** for versioning systems
7. **Apply middleware at group level** rather than individual routes
8. **Initialize dependencies** in the correct order during startup

## Anti-Patterns to Avoid

1. **Don't put business logic in routers** - keep routers clean
2. **Don't use struct-based controllers** - use function-based controllers
3. **Don't hardcode database connections** - use the global `model.DB`
4. **Don't skip input validation** - always validate and sanitize inputs
5. **Don't ignore transaction rollbacks** - handle them properly
6. **Don't mix authentication methods** - follow established JWT/WebAuthn patterns
7. **Don't create duplicate middleware** - reuse existing middleware functions

This guide should help AI coding agents understand and maintain consistency with the existing codebase architecture and patterns.
