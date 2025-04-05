# Quick Setup Guide for IPSwamp Honeypot

## Prerequisites

- curl or wget
- bash shell
- IPSwamp Honeypot API Key
- IPSwamp Honeypot ID (optional, auto-generated if not provided)

## Installation Options

### Interactive Installation (Recommended for First-Time Users)

```bash
# Download and run installation script
curl -sSL https://raw.githubusercontent.com/haupt-pascal/ipswamp-honeypot/main/install.sh -o install.sh
chmod +x install.sh
./install.sh
```

The script will:

1. Install Docker if not present
2. Install Docker Compose if not present (optional)
3. Guide you through configuration:
   - API Key setup
   - Honeypot ID selection (auto-generated or custom)
4. Deploy and start the honeypot

### Non-Interactive Installation

```bash
./install.sh <API_KEY> [HONEYPOT_ID]
```

Examples:

```bash
# With API key only (Honeypot ID will be auto-generated)
./install.sh "your-api-key"

# With both API key and Honeypot ID
./install.sh "your-api-key" "custom-honeypot-id"
```

## Post-Installation

After successful installation, you'll see:

- Honeypot ID and confirmation
- List of deployed services and ports
- Instructions for monitoring and management

For detailed configuration options, see:

- [Docker Setup Guide](docker-setup.md) - after Docker installation
- [Bare Metal Setup Guide](bare-metal-setup.md) - for manual installation
