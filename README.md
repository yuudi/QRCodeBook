# QRCodeBook


## Build

```sh
go build -trimpath -ldflags="-s -w" -o "dist/qrcodebook" .
```

## Development

### Running Tests

```sh
go test ./... -v            # Run all tests
```

See **[Testing Guide](docs/TESTING.md)** for more information
