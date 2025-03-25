FROM node:18-alpine

WORKDIR /app

# Netzwerktools für Diagnose installieren
RUN apk add --no-cache curl iputils bind-tools netcat-openbsd

# Abhängigkeiten installieren
COPY package*.json ./
RUN npm install

# Anwendungscode kopieren
COPY . .

# Ports für HTTP, SSH und FTP freigeben
EXPOSE 8080
EXPOSE 2222
EXPOSE 21
EXPOSE 9229

# Umgebungsvariablen setzen
ENV NODE_ENV=production \
    HONEYPOT_ID="test" \
    API_KEY="e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a" \
    API_ENDPOINT="https://api.ipswamp.com/api" \
    HEARTBEAT_INTERVAL=60000 \
    HEARTBEAT_RETRY_COUNT=3 \
    HEARTBEAT_RETRY_DELAY=5000

# Logverzeichnis und FTP-Verzeichnis erstellen
RUN mkdir -p logs ftp

# Container starten
CMD ["node", "src/index.js"]
