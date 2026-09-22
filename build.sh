#!/usr/bin/env bash
# Vet, test, then build bin/san_tunnels.exe (Windows) and bin/san_tunnels (Linux).
set -euo pipefail

cd "$(dirname "$0")"

version="$(date +%Y.%m.%d-%H%M)"
ldflags="-X main.version=${version}"

echo "vet..."
go vet ./...

echo "test..."
go test ./...

mkdir -p bin

echo "build windows/amd64..."
GOOS=windows GOARCH=amd64 go build -ldflags "${ldflags}" -o bin/san_tunnels.exe ./cmd/san_tunnels

echo "build linux/amd64..."
GOOS=linux GOARCH=amd64 go build -ldflags "${ldflags}" -o bin/san_tunnels ./cmd/san_tunnels

echo "built bin/san_tunnels.exe and bin/san_tunnels (${version})"
