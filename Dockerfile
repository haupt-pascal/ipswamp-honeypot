FROM node:18-alpine

WORKDIR /app

# Netzwerktools für Diagnose installieren
RUN apk add --no-cache curl iputils bind-tools netcat-openbsd

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

# Define build arguments for sensitive values - no defaults for security
ARG HONEYPOT_ID
ARG API_KEY
ARG API_ENDPOINT

# Umgebungsvariablen setzen
ENV NODE_ENV=production \
    HONEYPOT_ID=${HONEYPOT_ID} \
    API_KEY=${API_KEY} \
    API_ENDPOINT=${API_ENDPOINT} \
    HEARTBEAT_INTERVAL=60000 \
    HEARTBEAT_RETRY_COUNT=3 \
    HEARTBEAT_RETRY_DELAY=5000

# Logverzeichnis und FTP-Verzeichnis erstellen
RUN mkdir -p logs ftp

# Container starten
CMD ["node", "src/index.js"]
