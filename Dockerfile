FROM node:18-alpine

WORKDIR /app

# Install network tools for diagnostics (added openssl)
RUN apk add --no-cache curl iputils bind-tools netcat-openbsd openssl

# Install dependencies
COPY package*.json ./
RUN npm install
# Add the missing dependency
RUN npm install node-forge

# Copy application code
COPY . .

# Expose ports for HTTP, SSH, and FTP
EXPOSE 8080
EXPOSE 2222
EXPOSE 21
EXPOSE 9229

# Don't define build arguments for sensitive values
# Set only non-sensitive environment defaults
ENV NODE_ENV=production \
    HEARTBEAT_INTERVAL=60000 \
    HEARTBEAT_RETRY_COUNT=3 \
    HEARTBEAT_RETRY_DELAY=5000

# Create log directory and FTP directory
RUN mkdir -p logs ftp

# Start container
CMD ["node", "src/index.js"]
