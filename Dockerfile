FROM node:18-alpine

WORKDIR /app

# Netzwerktools für Diagnose installieren (added openssl)
RUN apk add --no-cache curl iputils bind-tools netcat-openbsd openssl

# Abhängigkeiten installieren
COPY package*.json ./
RUN npm install
# Add the missing dependency
RUN npm install node-forge

# Anwendungscode kopieren
COPY . .

# Ports für HTTP, SSH und FTP freigeben
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

# Logverzeichnis und FTP-Verzeichnis erstellen
RUN mkdir -p logs ftp

# Container starten
CMD ["node", "src/index.js"]
