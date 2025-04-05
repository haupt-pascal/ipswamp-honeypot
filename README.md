# Modular Honeypot

A modular honeypot service that detects suspicious activities and reports them to the API. This honeypot is packaged in Docker and can be easily extended.

```bash
curl -X POST "https://api.ipswamp.com/api/honeypot/heartbeat?api_key=e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a" \
  -H "Content-Type: application/json" \
  -d '{"honeypot_id": "2"}'
```

## Features

- HTTP honeypot with simulated vulnerabilities
- Detection of various attack patterns (SQL injection, command injection, XSS, etc.)
- Regular heartbeats to the API servers
- Reporting of suspicious activities
- Extensible architecture for additional services

## Installation and Start

### Automatic Installation

The easiest way to install the honeypot is to use the automatic installation script:

```bash
# Download and run the installation script
curl -sSL https://raw.githubusercontent.com/haupt-pascal/ipswamp-honeypot/main/install.sh -o install.sh
chmod +x install.sh
./install.sh <API_KEY> [HONEYPOT_ID]
```

The installation script:

- Detects your operating system (Linux, macOS)
- Installs all dependencies (Docker, Docker Compose)
- Configures the honeypot with your API key
- Starts the honeypot service

### Manual Installation

#### Prerequisites

- Docker and Docker Compose
- A running instance of the backend server

### Configuration

Configuration is done via environment variables that can be set in the `docker-compose.yml` file or directly when starting the container:

- `HONEYPOT_ID`: The ID of the honeypot (default: "test")
- `API_KEY`: The API key for communication with the backend
- `API_ENDPOINT`: The URL of the API endpoint (e.g., "http://api-server:3000/api")
- `HEARTBEAT_INTERVAL`: The interval for heartbeats in milliseconds (default: 60000)
- `HTTP_PORT`: The port for the HTTP server (default: 8080)

### Starting the Container

```bash
# With Docker Compose (recommended)
docker compose up -d

# Or manually with Docker
docker build -t honeypot .
docker run -d -p 8080:8080 \
  -e HONEYPOT_ID=test \
  -e API_KEY=e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a \
  -e API_ENDPOINT=http://api-server:3000/api \
  --name honeypot \
  honeypot
```

## Architecture

The honeypot consists of several components:

- `index.js`: The main file that starts the server and loads the modules
- `modules/`: Directory for the various honeypot modules
  - `http-honeypot.js`: HTTP honeypot module
- `services/`: Services for communication with the backend
  - `api-service.js`: Service for API communication
- `utils/`: Helper functions
  - `logger.js`: Logger configuration

## Extension with Additional Services

The honeypot can be easily extended with additional services. Follow these steps:

1. Create a new module in `src/modules/` (e.g., `ssh-honeypot.js`)
2. Implement the corresponding functionality
3. Import and initialize the module in `src/index.js`
4. Add the required port exposures in `Dockerfile` and `docker-compose.yml`

### Example for an SSH Honeypot Module

```javascript
// src/modules/ssh-honeypot.js
const { Server } = require("ssh2");
const fs = require("fs");

function setupSSHHoneypot(logger, config, reportAttack) {
  // SSH server implementation
  // ...
}

module.exports = { setupSSHHoneypot };
```

## Logs

The logs are stored in the `logs/` directory and include:

- `honeypot.log`: General logs
- `error.log`: Error logs
- `attacks.log`: Detected attacks

## Monitoring

The honeypot has a monitoring endpoint at `/monitor` that shows the status of the service.

---

Developed for communication with the IPDB backend.
