FROM node:18-alpine

WORKDIR /app

# Abhängigkeiten installieren
COPY package*.json ./
RUN npm install

# Anwendungscode kopieren
COPY . .

# Ports für HTTP und SSH freigeben
EXPOSE 8080
EXPOSE 2222

# Umgebungsvariablen setzen
ENV NODE_ENV=production \
    HONEYPOT_ID="test" \
    API_KEY="e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a" \
    API_ENDPOINT="https://api.ipswamp.com/api" \
    HEARTBEAT_INTERVAL=60000

# Container starten
CMD ["node", "src/index.js"]