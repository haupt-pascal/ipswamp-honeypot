# Modularer Honeypot

Ein modularer Honeypot-Service, der verdächtige Aktivitäten erkennt und an die API meldet. Dieser Honeypot ist in Docker verpackt und kann leicht erweitert werden.

```bash
curl -X POST "https://api.ipswamp.com/api/honeypot/heartbeat?api_key=e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a" \
  -H "Content-Type: application/json" \
  -d '{"honeypot_id": "2"}'
```

## Funktionen

- HTTP-Honeypot mit simulierten Schwachstellen
- Erkennung verschiedener Angriffsmuster (SQL-Injection, Command-Injection, XSS, etc.)
- Regelmäßige Heartbeats an die API-Server
- Meldung von verdächtigen Aktivitäten
- Erweiterbare Architektur für zusätzliche Dienste

## Installation und Start

### Voraussetzungen

- Docker und Docker Compose
- Eine laufende Instanz des Backend-Servers

### Konfiguration

Die Konfiguration erfolgt über Umgebungsvariablen, die in der `docker-compose.yml` Datei oder direkt beim Starten des Containers gesetzt werden können:

- `HONEYPOT_ID`: Die ID des Honeypots (Standard: "test")
- `API_KEY`: Der API-Schlüssel für die Kommunikation mit dem Backend
- `API_ENDPOINT`: Die URL des API-Endpoints (z.B. "http://api-server:3000/api")
- `HEARTBEAT_INTERVAL`: Das Intervall für Heartbeats in Millisekunden (Standard: 60000)
- `HTTP_PORT`: Der Port für den HTTP-Server (Standard: 8080)

### Container starten

```bash
# Mit Docker Compose
docker-compose up -d

# Oder manuell mit Docker
docker build -t honeypot .
docker run -d -p 8080:8080 \
  -e HONEYPOT_ID=test \
  -e API_KEY=e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a \
  -e API_ENDPOINT=http://api-server:3000/api \
  --name honeypot \
  honeypot
```

## Architektur

Der Honeypot besteht aus mehreren Komponenten:

- `index.js`: Die Hauptdatei, die den Server startet und die Module lädt
- `modules/`: Verzeichnis für die verschiedenen Honeypot-Module
  - `http-honeypot.js`: HTTP-Honeypot-Modul
- `services/`: Dienste für die Kommunikation mit dem Backend
  - `api-service.js`: Service für die API-Kommunikation
- `utils/`: Hilfsfunktionen
  - `logger.js`: Logger-Konfiguration

## Erweiterung mit zusätzlichen Diensten

Der Honeypot kann leicht um zusätzliche Dienste erweitert werden. Folge diesen Schritten:

1. Erstelle ein neues Modul in `src/modules/` (z.B. `ssh-honeypot.js`)
2. Implementiere die entsprechende Funktionalität
3. Importiere und initialisiere das Modul in `src/index.js`
4. Füge die benötigten Port-Freigaben in `Dockerfile` und `docker-compose.yml` hinzu

### Beispiel für ein SSH-Honeypot-Modul

```javascript
// src/modules/ssh-honeypot.js
const { Server } = require('ssh2');
const fs = require('fs');

function setupSSHHoneypot(logger, config, reportAttack) {
  // SSH-Server-Implementierung
  // ...
}

module.exports = { setupSSHHoneypot };
```

## Logs

Die Logs werden im Verzeichnis `logs/` gespeichert und umfassen:

- `honeypot.log`: Allgemeine Logs
- `error.log`: Fehler-Logs
- `attacks.log`: Erkannte Angriffe

## Monitoring

Der Honeypot verfügt über einen Monitoring-Endpunkt unter `/monitor`, der den Status des Dienstes anzeigt.

---

Entwickelt für die Kommunikation mit dem IPDB-Backend.
