#!/bin/bash
# Network debugging script for IPSwamp Honeypot
# This script helps diagnose Docker networking issues

# Print container info
echo "===== Container Network Information ====="
hostname
ip addr
echo ""

# Check DNS resolution
echo "===== DNS Resolution Tests ====="
echo "host.docker.internal:"
getent hosts host.docker.internal || echo "Not found in hosts"
echo ""

echo "hono:"
getent hosts hono || echo "Not found in hosts"
echo ""

echo "host-gateway:"
getent hosts host-gateway || echo "Not found in hosts"
echo ""

# Try to connect to common endpoints
echo "===== Connection Tests ====="
echo "Testing connection to host.docker.internal:3001..."
curl -v --connect-timeout 5 http://host.docker.internal:3001 2>&1 | grep -E "Connected|Failed|refused"
echo ""

echo "Testing connection to hono:3001..."
curl -v --connect-timeout 5 http://hono:3001 2>&1 | grep -E "Connected|Failed|refused"
echo ""

echo "Testing localhost:3001..."
curl -v --connect-timeout 5 http://localhost:3001 2>&1 | grep -E "Connected|Failed|refused"
echo ""

# List all network interfaces and routes
echo "===== Routes and Interfaces ====="
ip route
echo ""

# List all Docker networks
echo "===== Docker Networks ====="
cat /etc/hosts
echo ""

# Test the API specifically (with both http and native methods)
echo "===== API Specific Tests ====="
echo "Testing API endpoint GET with http module..."
node -e "
const http = require('http');
const options = {
  hostname: 'hono',
  port: 3001,
  path: '/api/ping',
  method: 'GET',
  timeout: 5000
};
const req = http.request(options, (res) => {
  console.log(\`Status: \${res.statusCode}\`);
  res.on('data', (chunk) => {
    console.log(\`Response: \${chunk}\`);
  });
});
req.on('error', (e) => {
  console.error(\`Error: \${e.message}\`);
});
req.end();
" 2>&1

echo ""
echo "Done with network diagnostics"
