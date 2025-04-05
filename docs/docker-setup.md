# Docker Setup Guide for IPSwamp Honeypot

## Prerequisites

- IPSwamp Honeypot API Key
- IPSwamp Honeypot ID
- Docker (installed by setup script if needed)
- Docker Compose (optional, installed by setup script if needed)

## Important Configuration

### Honeypot ID

Each honeypot instance must have a unique identifier. This ID is used to:

- Track attacks across your honeypot network
- Distinguish between different honeypot instances
- Associate collected data with specific honeypots

**⚠️ Warning:** Never deploy multiple honeypots with the same ID!

## Quick Start

```bash
# Replace YOUR_UNIQUE_ID with a unique identifier for this honeypot
docker run -d --name ipswamp-honeypot \
  -e API_KEY=your_api_key \
  -e HONEYPOT_ID=YOUR_UNIQUE_ID \
  -p 8080:8080 -p 2222:2222 -p 21:21 \
  ghcr.io/haupt-pascal/ipswamp-honeypot:latest
```

## Using Docker Compose (Recommended)

1. Create docker-compose.yaml:

```yaml
version: "3.8"
services:
  honeypot:
    image: ghcr.io/haupt-pascal/ipswamp-honeypot:latest
    container_name: ipswamp-honeypot
    restart: unless-stopped
    environment:
      - API_KEY=your_api_key
      - HONEYPOT_ID=YOUR_UNIQUE_ID # Required - set a unique identifier
      - ENABLE_HTTP=true
      - ENABLE_HTTPS=true
      - ENABLE_SSH=true
      - ENABLE_FTP=true
      - ENABLE_MAIL=true
      - ENABLE_MYSQL=true
    ports:
      - "8080:8080" # HTTP
      - "8443:8443" # HTTPS
      - "2222:2222" # SSH
      - "21:21" # FTP
      - "25:25" # SMTP
      - "587:587" # SMTP Submission
      - "110:110" # POP3
      - "143:143" # IMAP
      - "3306:3306" # MySQL
    volumes:
      - ./logs:/app/logs
      - ./ftp:/app/ftp
      - ./mail:/app/mail
      - ./mysql:/app/mysql
```

2. Start the container:

```bash
docker compose up -d
```

## Configuration

### Required Environment Variables

| Variable    | Description                   | Required |
| ----------- | ----------------------------- | -------- |
| HONEYPOT_ID | Your IPSwamp Honeypot ID      | Yes      |
| API_KEY     | Your IPSwamp Honeypot API Key | Yes      |

### Optional Environment Variables

| Variable     | Default | Description           |
| ------------ | ------- | --------------------- |
| ENABLE_HTTP  | true    | Enable HTTP honeypot  |
| ENABLE_HTTPS | true    | Enable HTTPS honeypot |
| ENABLE_SSH   | true    | Enable SSH honeypot   |
| ENABLE_FTP   | true    | Enable FTP honeypot   |
| ENABLE_MAIL  | true    | Enable mail honeypots |
| ENABLE_MYSQL | true    | Enable MySQL honeypot |

## Monitoring

```bash
# View logs
docker logs -f ipswamp-honeypot

# Check status
docker exec ipswamp-honeypot curl localhost:8080/monitor
```

## Updating

```bash
# Pull latest image
docker pull ghcr.io/haupt-pascal/ipswamp-honeypot:latest

# Restart container
docker compose down && docker compose up -d
```

## Troubleshooting

### Port Conflicts

If you see "port is already allocated" errors, change the port mapping in docker-compose.yaml:

```yaml
ports:
  - "8081:8080" # Change left number
```

### API Connection Issues

1. Verify API key is correct
2. Check container logs
3. Ensure outbound connectivity
