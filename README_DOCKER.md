# Snibble Client - Docker Setup

This Docker setup allows users to run the Snibble client without installing any dependencies on their local machine. The setup uses Alpine Linux for a lightweight container.

## Prerequisites

- Docker
- Docker Compose (optional, but recommended)

## Quick Start

### Option 1: Using Docker Compose (Recommended)

1. **Build and run the application:**
   ```bash
   docker-compose up --build
   ```

2. **Access the GUI:**
   - The application runs with a VNC server on port 5900
   - Connect using any VNC client (like TigerVNC, RealVNC, or TightVNC)
   - Connection details:
     - Host: `localhost:5900`
     - Password: `appuser`

### Option 2: Using Docker directly

1. **Build the image:**
   ```bash
   docker build -t snibble-client .
   ```

2. **Run the container:**
   ```bash
   docker run -p 5900:5900 snibble-client
   ```

3. **Access the GUI:** Same as above

## VNC Clients

### Linux
```bash
# Install TigerVNC
sudo apt install tigervnc-viewer  # Ubuntu/Debian
sudo dnf install tigervnc         # Fedora

# Connect
vncviewer localhost:5900
```

### Windows
- Download and install [TigerVNC](https://tigervnc.org/)
- Connect to `localhost:5900`

### macOS
```bash
# Install via Homebrew
brew install --cask tigervnc-viewer

# Connect
vncviewer localhost:5900
```

### Web Browser (noVNC)
You can also add noVNC for web-based access by modifying the docker-compose.yml:

```yaml
services:
  snibble-client:
    # ... existing config ...
  
  novnc:
    image: theasp/novnc:latest
    environment:
      - DISPLAY_WIDTH=1024
      - DISPLAY_HEIGHT=768
    ports:
      - "8080:8080"
    depends_on:
      - snibble-client
```

Then access via: http://localhost:8080

## Configuration

### Environment Variables
Place your `.env` file in the client directory with the following variables:
```
AUTH_SERVER_HOST=your_auth_server_host
AUTH_SERVER_PORT=your_auth_server_port
CHAT_SERVER_HOST=your_chat_server_host
CHAT_SERVER_PORT=your_chat_server_port
# Add other configuration variables as needed
```

### Persistent Data
To persist application data, you can mount volumes:

```yaml
services:
  snibble-client:
    # ... existing config ...
    volumes:
      - ./data:/home/appuser/.local/share/snibble
      - ./.env:/home/appuser/.env:ro
```

## Troubleshooting

### Common Issues

1. **Build fails due to missing dependencies:**
   - Ensure you have a stable internet connection
   - The build process downloads and compiles dependencies from source

2. **VNC connection refused:**
   - Wait a few seconds after starting the container for VNC to initialize
   - Check if port 5900 is already in use: `netstat -an | grep 5900`

3. **Application doesn't start:**
   - Check container logs: `docker logs <container_name>`
   - Ensure the .env file is properly configured

4. **Display issues:**
   - Try different VNC clients
   - Adjust display resolution in the Dockerfile if needed

### Debug Mode
To run the container in debug mode:

```bash
docker run -it --entrypoint /bin/bash snibble-client
```

This gives you a shell inside the container to troubleshoot issues.

## Building for Different Architectures

### Multi-platform build (ARM64 + AMD64)
```bash
# Create a builder
docker buildx create --name multiarch --use

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 -t snibble-client:latest .
```

## Optimization Tips

1. **Reduce image size:**
   - The Alpine Linux base keeps the image small
   - Multi-stage build separates build and runtime dependencies

2. **Faster builds:**
   - Use `.dockerignore` to exclude unnecessary files
   - Cache dependencies by copying requirements first

3. **Security:**
   - The application runs as a non-root user (`appuser`)
   - VNC password should be changed in production

## Production Deployment

For production deployment, consider:

1. **Use secrets management** for sensitive configuration
2. **Set up proper networking** between client and server containers
3. **Configure resource limits** in docker-compose.yml:
   ```yaml
   deploy:
     resources:
       limits:
         memory: 512M
         cpus: '1.0'
   ```

4. **Use health checks:**
   ```yaml
   healthcheck:
     test: ["CMD", "pgrep", "Snibble"]
     interval: 30s
     timeout: 10s
     retries: 3
   ```

## Development

To develop with this setup:

1. **Mount source code** for live editing:
   ```yaml
   volumes:
     - ./src:/app/src:ro
   ```

2. **Use development build** with debug symbols:
   ```dockerfile
   RUN cmake .. -DCMAKE_BUILD_TYPE=Debug -G Ninja
   ```

3. **Enable X11 forwarding** for native display (Linux only):
   ```bash
   docker run -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix snibble-client
   ```
