# Gateway Service Demo

A microservices gateway demo with GitHub OAuth authentication, request proxying, and validation.

## Architecture

- **Gateway Service** (`:8080`) - Main entry point with auth validation and request routing
- **Auth Service** (`:8081`) - GitHub OAuth authentication handler  
- **Demo Service** (`:8082`) - Backend API with public/private endpoints
- **Frontend** (`:3000`) - Static web interface

## Quick Start

1. **Setup GitHub OAuth App:**
   - Go to GitHub Settings > Developer settings > OAuth Apps
   - Create OAuth App with callback: `http://localhost:8081/auth/callback`
   - Update `.env` with your credentials

2. **Run all services:**
   ```bash
   ./run-services.sh
   ```

3. **Access the demo:**
   - Open `http://localhost:3000`
   - Login with GitHub
   - Test API endpoints

## API Endpoints

- `GET /api/public` - No authentication required
- `GET /api/private` - Requires authentication
- `GET /api/user` - Returns user-specific data

## Features

- **Centralized Authentication** - Single OAuth flow for all services
- **Request Proxying** - Gateway routes requests to appropriate services
- **Header Injection** - Adds user context to downstream requests
- **CORS Handling** - Cross-origin request support
- **Error Handling** - Graceful failure responses