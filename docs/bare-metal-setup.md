# Bare Metal Setup Guide for IPSwamp Honeypot

## Prerequisites

- Linux or macOS
- Node.js 16+
- Git
- IPSwamp Honeypot API Key
- IPSwamp Honeypot ID

## Manual Installation

1. Clone repository:

```bash
git clone https://github.com/haupt-pascal/ipswamp-honeypot.git
cd ipswamp-honeypot
```

2. Install dependencies:

```bash
npm install
```

3. Configure environment:

### Important: Honeypot ID Configuration

Each honeypot instance must have a unique identifier. Set this in your .env file:

```bash
cat > .env << EOF
API_KEY=your_honeypot_api_key    # Your IPSwamp Honeypot API Key
HONEYPOT_ID=your_honeypot_id     # Your IPSwamp Honeypot ID
ENABLE_HTTP=true
ENABLE_HTTPS=true
ENABLE_SSH=true
ENABLE_FTP=true
ENABLE_MAIL=true
ENABLE_MYSQL=true
EOF
```

4. Start services:

```bash
npm start
```

## Configuration

### Required Ports

| Service | Port    |
| ------- | ------- |
| HTTP    | 8080    |
| HTTPS   | 8443    |
| SSH     | 2222    |
| FTP     | 21      |
| SMTP    | 25, 587 |
| POP3    | 110     |
| IMAP    | 143     |
| MySQL   | 3306    |

### Directory Structure

```
/opt/ipswamp/
├── logs/
├── ftp/
├── mail/
└── mysql/
```

## Service Management

### Using systemd

Create service file:

```bash
sudo cat > /etc/systemd/system/ipswamp.service << EOF
[Unit]
Description=IPSwamp Honeypot
After=network.target

[Service]
Type=simple
User=ipswamp
WorkingDirectory=/opt/ipswamp
ExecStart=/usr/bin/npm start
Restart=always

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start:

```bash
sudo systemctl enable ipswamp
sudo systemctl start ipswamp
```

## Monitoring

```bash
# View logs
tail -f /opt/ipswamp/logs/honeypot.log

# Check status
curl localhost:8080/monitor
```

## Updating

```bash
cd /opt/ipswamp
git pull
npm install
sudo systemctl restart ipswamp
```

## Troubleshooting

### Permission Issues

```bash
# Set correct ownership
sudo chown -R ipswamp:ipswamp /opt/ipswamp

# Set correct permissions
sudo chmod 755 /opt/ipswamp
```

### Port Conflicts

Check for occupied ports:

```bash
sudo lsof -i :<PORT>
```

### Service Issues

Check service status:

```bash
sudo systemctl status ipswamp
journalctl -u ipswamp
```
