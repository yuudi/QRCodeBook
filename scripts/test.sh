#!/bin/bash

# QRCodeBook Test Runner
# Convenient script for running various test scenarios

set -e

echo "🧪 QRCodeBook Test Suite"
echo "======================="

case "${1:-all}" in
    "all")
        echo "📦 Running all tests..."
        go test ./... -v
        echo ""
        echo "📊 Coverage Report:"
        go test ./... -cover
        ;;
    "utils")
        echo "🔧 Testing utility functions..."
        go test ./src/utils -v -cover
        ;;
    "controllers")
        echo "🌐 Testing HTTP controllers..."
        go test ./src/internal/controller -v -cover
        ;;
    "jwt")
        echo "🔐 Testing JWT functions..."
        go test ./src/utils -v -run "JWT"
        ;;
    "crypto")
        echo "🔒 Testing cryptographic functions..."
        go test ./src/utils -v -run "Crypto|Hmac|Encrypt|Decrypt"
        ;;
    "auth")
        echo "🚪 Testing authentication controllers..."
        go test ./src/internal/controller -v -run "Login|Register"
        ;;
    "bench")
        echo "⚡ Running performance benchmarks..."
        go test ./... -bench=. -benchmem
        ;;
    "race")
        echo "🏃 Running race condition detection..."
        go test ./... -race
        ;;
    "coverage")
        echo "📈 Generating detailed coverage report..."
        go test ./... -coverprofile=coverage.out
        go tool cover -html=coverage.out -o coverage.html
        echo "Coverage report generated: coverage.html"
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  all         Run all tests (default)"
        echo "  utils       Test utility functions only"
        echo "  controllers Test HTTP controllers only"
        echo "  jwt         Test JWT functions only"
        echo "  crypto      Test cryptographic functions only"
        echo "  auth        Test authentication endpoints only"
        echo "  bench       Run performance benchmarks"
        echo "  race        Run with race condition detection"
        echo "  coverage    Generate detailed coverage report"
        echo "  help        Show this help message"
        ;;
    *)
        echo "❌ Unknown command: $1"
        echo "Use '$0 help' for available commands"
        exit 1
        ;;
esac
