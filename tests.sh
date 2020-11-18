#!/bin/sh
set -e

echo "Building all go files"
go build ./...
echo "Success building all go files"

echo "Running go unit tests"
go test -tags=unit ./...
echo "Success running go unit tests"

echo "Building applications"
go build ./cmd/edge-proxy
echo "Success building applications"

echo "Building docker images"
docker build --no-cache . -f Dockerfile
echo "Success building docker images"