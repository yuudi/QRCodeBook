# QRCodeBook

A secure authentication system supporting both password-based and WebAuthn authentication methods.

## Build

```sh
go build -trimpath -ldflags="-s -w" -o "dist/qrcodebook" .
```

## Development

### Running Tests

```sh
# Using the test script (recommended)
./scripts/test.sh           # Run all tests
./scripts/test.sh utils     # Test utilities only
./scripts/test.sh auth      # Test authentication only
./scripts/test.sh coverage  # Generate coverage report

# Direct go test commands
go test ./... -v            # Run all tests
go test ./... -cover        # Run tests with coverage
go test ./src/utils -v      # Test specific package
```

### Documentation

- **[Testing Guide](docs/TESTING.md)** - Comprehensive testing documentation including coverage analysis and best practices