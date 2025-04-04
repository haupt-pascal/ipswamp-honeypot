# IPSwamp Honeypot - Comprehensive Debugging and Development Guide

This document provides comprehensive instructions for debugging, developing, and extending the IPSwamp Honeypot system.

## Table of Contents

1. [Setup Development Environment](#setup-development-environment)
2. [Debugging Techniques](#debugging-techniques)
3. [Logging System](#logging-system)
4. [Adding New Modules](#adding-new-modules)
5. [Environment Variables Reference](#environment-variables-reference)
6. [Troubleshooting Common Issues](#troubleshooting-common-issues)
7. [Simulating Attacks for Testing](#simulating-attacks-for-testing)
8. [Monitoring & Troubleshooting](#monitoring--troubleshooting)
9. [Module-Specific Debugging](#module-specific-debugging)
10. [API Communication Debugging](#api-communication-debugging)

## Setup Development Environment

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/ipswamp-honeypot.git
cd ipswamp-honeypot

# Install dependencies
npm install

# Start in development mode
npm run dev
```

### Running with Docker for Development

```bash
# Build the image with development tag
docker build -t honeypot:dev .

# Run with development settings and port mapping
docker run -p 8080:8080 -p 2222:2222 -p 21:21 \
  -e NODE_ENV=development \
  -e LOG_LEVEL=debug \
  -v $(pwd)/src:/app/src \
  -v $(pwd)/logs:/app/logs \
  --name honeypot-dev \
  honeypot:dev
```

### Mounting Source Code for Live Editing

For active development, you can mount your source code into the container:

```bash
docker-compose -f docker-compose.dev.yaml up
```

## Debugging Techniques

### Enable Debug Logging

Set the `LOG_LEVEL` environment variable to `debug` for more verbose output:

```bash
LOG_LEVEL=debug npm run dev
```

Or in Docker:

```bash
docker run -e LOG_LEVEL=debug -p 8080:8080 -p 2222:2222 honeypot
```

### Real-time Log Monitoring

```bash
# Follow the logs in real-time
tail -f logs/honeypot.log

# Follow only attack logs
tail -f logs/attacks.log

# Use grep to filter logs
tail -f logs/honeypot.log | grep "SSH"

# Filter logs by module type
tail -f logs/honeypot.log | grep "HTTP"
tail -f logs/honeypot.log | grep "FTP"
tail -f logs/honeypot.log | grep "MySQL"
```

### Using Debug Endpoint

The honeypot includes a special debug endpoint `/monitor` that provides information about the running services:

```
http://localhost:8080/monitor
```

This returns JSON data about the current state of the honeypot.

### Remote Debugging with Node.js

To enable remote debugging:

```bash
# Start with debug flag
node --inspect src/index.js

# Or for Docker
docker run -p 8080:8080 -p 2222:2222 -p 9229:9229 \
  -e NODE_ENV=development \
  --name honeypot-debug \
  honeypot:dev \
  node --inspect=0.0.0.0:9229 src/index.js
```

Then connect using Chrome DevTools at `chrome://inspect` or VS Code.

## Logging System

The honeypot uses Winston for logging with multiple transport layers:

- `honeypot.log`: All logs (info level and above)
- `error.log`: Error logs only
- `attacks.log`: Attack-related logs (warn level and above)

### Log Levels

- `error`: Errors that require attention
- `warn`: Attacks and suspicious activities
- `info`: Normal operational information
- `debug`: Detailed debugging information
- `silly`: Very verbose logging (not recommended in production)

### Adding Custom Logging

You can add custom logging to any module:

```javascript
// Example logging in a new module
logger.info("FTP connection received", { ip: clientIP, port: clientPort });
logger.warn("Possible FTP attack detected", {
  ip: clientIP,
  command: receivedCommand,
});
```

## Adding New Modules

The honeypot is designed to be modular. Follow these steps to add a new service:

1. Create a new module file in `src/modules/` (e.g., `ftp-honeypot.js`)
2. Implement the module using the appropriate libraries
3. Update `src/index.js` to load and initialize your module
4. Add any required ports to `Dockerfile` and `docker-compose.yaml`

### FTP Module Example Structure

```javascript
// Basic structure for an FTP honeypot module
const ftpd = require("ftpd"); // You'll need to add this dependency

function setupFTPHoneypot(logger, config, reportAttack) {
  // Implementation here
  logger.info("FTP Honeypot starting...");

  // Create FTP server
  // Handle connections
  // Log and report attacks

  return ftpServer; // Return the server instance
}

module.exports = { setupFTPHoneypot };
```

### Integrating the Module

In `src/index.js`, you'll need to:

```javascript
// Import the new module
const { setupFTPHoneypot } = require("./modules/ftp-honeypot");

// Initialize it after other modules
setupFTPHoneypot(logger, config, reportAttack);
```

## Environment Variables Reference

| Variable             | Description                          | Default                     |
| -------------------- | ------------------------------------ | --------------------------- |
| `NODE_ENV`           | Environment (development/production) | `production`                |
| `LOG_LEVEL`          | Logging level                        | `info`                      |
| `HONEYPOT_ID`        | ID for the honeypot instance         | `test`                      |
| `API_KEY`            | API key for backend communication    | -                           |
| `API_ENDPOINT`       | Backend API URL                      | `http://localhost:3000/api` |
| `HEARTBEAT_INTERVAL` | Interval for heartbeats in ms        | `60000`                     |
| `HTTP_PORT`          | Port for HTTP server                 | `8080`                      |
| `SSH_PORT`           | Port for SSH server                  | `2222`                      |
| `FTP_PORT`           | Port for FTP server                  | `21`                        |
| `HOST_IP`            | Host IP address                      | auto-detected               |

## Troubleshooting Common Issues

### Connection Refused

If you're seeing "Connection refused" errors:

1. Check if the service is running: `docker ps` or `netstat -tulpn`
2. Verify port mappings: `docker port honeypot`
3. Ensure no port conflicts with other services

### Module Not Loading

If a module fails to load:

1. Check the error logs: `cat logs/error.log`
2. Verify all dependencies are installed
3. Check syntax errors in the module file

### API Communication Failures

If the honeypot can't communicate with the backend:

1. Verify the `API_ENDPOINT` and `API_KEY` settings
2. Check network connectivity to the API server
3. Look for TLS/SSL issues if using HTTPS

### Resource Issues

If the honeypot is consuming too many resources:

1. Check memory usage: `docker stats honeypot`
2. Adjust logging levels to reduce disk I/O
3. Consider limiting the number of concurrent connections in busy modules

## Simulating Attacks for Testing

To properly test the honeypot functionality, you can simulate various types of attacks:

### HTTP Attacks

```bash
# SQL Injection attempt
curl "http://localhost:8080/login?username=admin'%20OR%201=1--"

# XSS attempt
curl "http://localhost:8080/search?q=<script>alert(1)</script>"

# Path traversal attempt
curl "http://localhost:8080/file?path=../../../etc/passwd"

# Credential harvesting test
curl -X POST -d "username=admin&password=password123" http://localhost:8080/login
```

### SSH Attacks

```bash
# Brute force login attempt
ssh admin@localhost -p 2222 # Try password: admin123
ssh root@localhost -p 2222  # Try password: password123

# Command execution (if you get access)
ssh user@localhost -p 2222
# Then try: cat /etc/passwd or other suspicious commands
```

### FTP Attacks

```bash
# Anonymous login attempt
ftp -P 21 localhost
# Use 'anonymous' as username with empty password

# Authenticated login with default credentials
ftp -P 21 localhost
# Use 'admin' / 'admin123' or 'user' / 'password123'

# Try to access sensitive directories
cd /private
get users.txt
```

## Monitoring & Troubleshooting

### Using the Monitor Endpoint

The honeypot provides a status endpoint at `/monitor` for checking system health:

```bash
# Access the monitor endpoint directly
curl http://localhost:8080/monitor
```

If you're getting a 404 error, check that the route is properly defined in `src/index.js` and isn't being overridden by another route handler.

### Disabling the Monitor Endpoint in Production

If you want to disable the monitor endpoint in production for security reasons:

```javascript
// In src/index.js - wrap the monitor endpoint in a condition
if (process.env.ENABLE_MONITOR === "true" || config.debugMode) {
  app.get("/monitor", (req, res) => {
    // Monitor endpoint code
  });
}
```

Then only enable it in development or testing environments:

```bash
# Only enable monitor in development
docker run -e ENABLE_MONITOR=true -e NODE_ENV=development -p 8080:8080 honeypot
```

## Module-Specific Debugging

### HTTP Module Debugging

To debug the HTTP module, follow these steps:

1. Enable debug logging for HTTP:

   ```bash
   LOG_LEVEL=debug npm run dev
   ```

2. Monitor HTTP-specific logs:

   ```bash
   tail -f logs/honeypot.log | grep "HTTP"
   ```

3. Use the monitor endpoint to check HTTP service status:
   ```bash
   curl http://localhost:8080/monitor
   ```

### SSH Module Debugging

To debug the SSH module, follow these steps:

1. Enable debug logging for SSH:

   ```bash
   LOG_LEVEL=debug npm run dev
   ```

2. Monitor SSH-specific logs:

   ```bash
   tail -f logs/honeypot.log | grep "SSH"
   ```

3. Use the monitor endpoint to check SSH service status:
   ```bash
   curl http://localhost:8080/monitor
   ```

### FTP Module Debugging

To debug the FTP module, follow these steps:

1. Enable debug logging for FTP:

   ```bash
   LOG_LEVEL=debug npm run dev
   ```

2. Monitor FTP-specific logs:

   ```bash
   tail -f logs/honeypot.log | grep "FTP"
   ```

3. Use the monitor endpoint to check FTP service status:
   ```bash
   curl http://localhost:8080/monitor
   ```

### MySQL Module Debugging

To debug the MySQL module, follow these steps:

1. Enable debug logging for MySQL:

   ```bash
   LOG_LEVEL=debug npm run dev
   ```

2. Monitor MySQL-specific logs:

   ```bash
   tail -f logs/honeypot.log | grep "MySQL"
   ```

3. Use the monitor endpoint to check MySQL service status:
   ```bash
   curl http://localhost:8080/monitor
   ```

## API Communication Debugging

### Debugging API Communication

To debug API communication issues, follow these steps:

1. Verify the `API_ENDPOINT` and `API_KEY` settings in your environment variables.

2. Enable debug logging for API communication:

   ```bash
   LOG_LEVEL=debug npm run dev
   ```

3. Monitor API-specific logs:

   ```bash
   tail -f logs/honeypot.log | grep "API"
   ```

4. Use the monitor endpoint to check API communication status:
   ```bash
   curl http://localhost:8080/monitor
   ```

## Testing Your Development Setup

1. **Verify Logging Works**: Generate some test events and check logs
2. **Test Each Module**: Connect to each service (HTTP, SSH, new modules)
3. **Simulate Attacks**: Use the examples above to trigger the detection systems
4. **API Integration**: Verify attack reports are sent to the backend API

## Best Practices for Development

- Create a separate branch for each new feature
- Write tests for new modules
- Document any new environment variables or configuration options
- Always use the logging system for important events
- Follow the existing code structure and patterns
