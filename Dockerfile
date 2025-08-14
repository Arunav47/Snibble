# Multi-stage build for C++ Qt Application
FROM alpine:3.18 as builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    cmake \
    pkgconfig \
    git \
    wget \
    curl \
    curl-dev \
    qt6-qtbase-dev \
    qt6-qttools-dev \
    jsoncpp-dev \
    libsecret-dev \
    hiredis-dev \
    openssl-dev \
    libsodium-dev \
    linux-headers \
    samurai

# Install jwt-cpp
WORKDIR /tmp
RUN git clone https://github.com/Thalhammer/jwt-cpp.git && \
    cd jwt-cpp && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) && \
    make install

# Install dotenv-cpp
RUN git clone https://github.com/laserpants/dotenv-cpp.git && \
    cd dotenv-cpp && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) && \
    make install

# Set working directory for the application
WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja && \
    ninja -j$(nproc)

# Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
    qt6-qtbase \
    qt6-qtbase-x11 \
    libcurl \
    jsoncpp \
    libsecret \
    hiredis \
    openssl \
    libsodium \
    xvfb \
    x11vnc \
    fluxbox \
    font-noto \
    ttf-dejavu \
    bash

# Create application user
RUN adduser -D -s /bin/bash appuser

# Copy built application from builder stage
COPY --from=builder /app/build/Snibble /usr/local/bin/Snibble

# Copy configuration files if they exist
RUN mkdir -p /home/appuser/
# Create a dummy .env file in builder stage and copy it
COPY --from=builder /app/ /tmp/app/
RUN if [ -f /tmp/app/.env ]; then cp /tmp/app/.env /home/appuser/.env; else touch /home/appuser/.env; fi

# Copy libraries and headers
COPY --from=builder /usr/local/lib/ /usr/local/lib/
COPY --from=builder /usr/local/include/ /usr/local/include/

# Update library cache
RUN ldconfig /usr/local/lib

# Set up VNC for GUI access
RUN mkdir -p /home/appuser/.vnc && \
    echo "appuser" | x11vnc -storepasswd /home/appuser/.vnc/passwd && \
    chmod 600 /home/appuser/.vnc/passwd && \
    chown -R appuser:appuser /home/appuser

# Switch to application user
USER appuser
WORKDIR /home/appuser

# Expose VNC port
EXPOSE 5900

# Create startup script
RUN echo '#!/bin/bash\n\
export DISPLAY=:1\n\
Xvfb :1 -screen 0 1024x768x24 &\n\
sleep 2\n\
fluxbox &\n\
sleep 2\n\
x11vnc -display :1 -nopw -listen localhost -xkb -rfbport 5900 -forever -shared &\n\
exec Snibble' > /home/appuser/start.sh

RUN chmod +x /home/appuser/start.sh

# Start the application
CMD ["/home/appuser/start.sh"]
