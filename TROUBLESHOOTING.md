# Troubleshooting for IPSwamp Honeypot

## Docker Installation Issues

### Docker Requires sudo to Run

If you can't run Docker without sudo after installation:

```bash
# Add your user to the Docker group
sudo usermod -aG docker $USER

# Log out and back in, or run the following command to apply changes
newgrp docker
```

### Docker Compose vs docker-compose

Starting with Docker Compose V2, the command is `docker compose` (without hyphen) instead of `docker-compose`.

To check which version you have:

```bash
# For Docker Compose V2 plugin (recommended)
docker compose version

# For older standalone version
docker-compose --version
```

## Common Error Messages

### "Port is already allocated"

This error message means that a port is already in use. Change the ports in the Docker configuration:

```bash
# Check which application is using the port
sudo lsof -i :<PORT>

# Configure a different port in docker-compose.yaml
# Example: 8081:8080 instead of 8080:8080
```

### API Connection Issues

If the honeypot can't connect to the API:

1. Check your API key in the `.env` file
2. Make sure your firewall allows outgoing connections
3. Check API availability with a curl command:

```bash
curl -X POST "https://api.ipswamp.com/api/honeypot/heartbeat?api_key=YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"honeypot_id": "YOUR_HONEYPOT_ID"}'
```

## Logging and Monitoring

### View Container Logs

```bash
# View recent logs
docker logs honeypot

# Follow logs continuously
docker logs -f honeypot
```

### Check Status

```bash
# Container status
docker ps -a | grep honeypot

# Detailed information about the container
docker inspect honeypot

# Call the honeypot status API
curl http://localhost:8080/monitor
```

## Managing the Honeypot

### Restart the Honeypot

```bash
# With Docker Compose
docker compose restart honeypot

# Or with Docker directly
docker restart honeypot
```

### Change Configuration

1. Edit the `.env` file or the environment variables in the Docker command
2. Restart the honeypot

### Backup Data

All honeypot data is located in the mounted directories:

```bash
# Backup logs and data
tar -czvf honeypot-backup.tar.gz logs/ ftp/ mail/ mysql/
```
