#!/bin/bash

cd "$(dirname "$0")"

# Load environment variables from .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found"
    exit 1
fi

echo "Installing dependencies and starting services..."

# Install dependencies and start services
(cd auth-service && /usr/local/go/bin/go mod tidy && /usr/local/go/bin/go run main.go) &
(cd demo-service && /usr/local/go/bin/go mod tidy && /usr/local/go/bin/go run main.go) &
(cd gateway-service && /usr/local/go/bin/go mod tidy && /usr/local/go/bin/go run main.go) &
(cd frontend && python3 -m http.server 3000) &

echo "Services started on ports 8080, 8081, 8082"
echo "Press Ctrl+C to stop all services"

# Wait for all background processes
wait