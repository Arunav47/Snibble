#!/bin/bash

# Snibble Client Docker Build Script

set -e

echo "🐳 Building Snibble Client Docker Image..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    print_warning ".env file not found. Creating a template..."
    cat > .env << EOF
# Snibble Client Configuration
AUTH_SERVER_HOST=localhost
AUTH_SERVER_PORT=8080
CHAT_SERVER_HOST=localhost
CHAT_SERVER_PORT=8081

# Add your configuration here
EOF
    print_status "Template .env file created. Please edit it with your configuration."
fi

# Build the Docker image
print_status "Building Docker image..."
if docker build -t snibble-client:latest .; then
    print_status "✅ Docker image built successfully!"
else
    print_error "❌ Failed to build Docker image"
    exit 1
fi

# Ask if user wants to run the container
echo ""
read -p "Do you want to run the container now? (y/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Starting Snibble Client container..."
    
    # Check if port 5900 is already in use
    if netstat -an 2>/dev/null | grep -q ":5900 "; then
        print_warning "Port 5900 is already in use. Stopping any existing containers..."
        docker stop snibble-client 2>/dev/null || true
        docker rm snibble-client 2>/dev/null || true
    fi
    
    # Run the container
    if docker run -d --name snibble-client -p 5900:5900 snibble-client:latest; then
        print_status "✅ Container started successfully!"
        echo ""
        echo "🎉 Snibble Client is now running!"
        echo ""
        echo "📱 To connect to the GUI:"
        echo "   • Install a VNC client (TigerVNC, RealVNC, etc.)"
        echo "   • Connect to: localhost:5900"
        echo "   • Password: appuser"
        echo ""
        echo "🔧 Useful commands:"
        echo "   • View logs: docker logs snibble-client"
        echo "   • Stop container: docker stop snibble-client"
        echo "   • Remove container: docker rm snibble-client"
        echo ""
        
        # Wait a bit for the container to start
        sleep 3
        
        # Check if container is still running
        if docker ps | grep -q snibble-client; then
            print_status "Container is running and ready for VNC connections!"
        else
            print_error "Container stopped unexpectedly. Check logs with: docker logs snibble-client"
        fi
    else
        print_error "❌ Failed to start container"
        exit 1
    fi
fi

echo ""
print_status "Build script completed! 🚀"
