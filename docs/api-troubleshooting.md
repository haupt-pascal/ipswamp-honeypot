# API Troubleshooting Guide für IPSwamp Honeypot

Diese Anleitung hilft bei der Diagnose und Behebung von API-Verbindungsproblemen mit dem IPSwamp-Backend.

## Häufige Probleme und Lösungen

### 1. 403 Forbidden (Unzureichende Berechtigungen)

**Symptom:** Der Honeypot meldet "Fehler beim Senden des Heartbeats" mit Statuscode 403.

**Mögliche Ursachen:**

- Ungültiger API-Schlüssel
- Der API-Schlüssel hat nicht die erforderlichen Berechtigungen
- Die Honeypot-ID ist unbekannt oder nicht autorisiert

**Lösungen:**

1. Überprüfen Sie den API-Schlüssel in der Konfiguration (docker-compose.yaml oder Umgebungsvariablen)
2. Stellen Sie sicher, dass die Honeypot-ID korrekt ist
3. Generieren Sie im Backend einen neuen API-Schlüssel
4. Überprüfen Sie die Firewall-Einstellungen des API-Servers

### 2. Verbindungsprobleme (Connection Refused)

**Symptom:** Der Honeypot kann keine Verbindung zum API-Server herstellen.

**Mögliche Ursachen:**

- API-Server ist nicht erreichbar
- Falscher API-Endpunkt
- Netzwerkkonfigurationsprobleme (Firewall, DNS, etc.)

**Lösungen:**

1. Überprüfen Sie, ob der API-Server läuft
2. Versuchen Sie einen PING auf den Hostnamen
3. Testen Sie manuell mit curl:
   ```bash
   curl -X POST "https://api.ipswamp.com/api/honeypot/heartbeat?api_key=IHR_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"honeypot_id": "IHRE_HONEYPOT_ID"}'
   ```
4. Überprüfen Sie die Netzwerkeinstellungen im Docker-Container

### 3. HTTPS/SSL-Probleme

**Symptom:** Der Honeypot meldet SSL/TLS-bezogene Fehler bei der Verbindung zum API-Server.

**Mögliche Ursachen:**

- Selbstsigniertes Zertifikat
- Abgelaufenes Zertifikat
- Inkompatibilität mit der Node.js-Version

**Lösungen:**

1. Überprüfen Sie die Gültigkeit des Zertifikats
2. Fügen Sie ggf. Zertifikatausnahmen hinzu
3. Konfigurieren Sie Axios für unsichere Verbindungen (nur in der Entwicklung!)

## Diagnostische Tools

Der Honeypot bietet verschiedene Diagnosetools zur Fehlerbehebung:

### API-Diagnostik-Endpunkt

Im Debug-Modus ist der Endpunkt `/api-diagnostics` verfügbar:

```
http://localhost:8080/api-diagnostics
```

Dieser liefert detaillierte Informationen über:

- API-Endpunktkonfiguration
- Letzten Heartbeat-Status
- API-Verbindungstest
- Fehlermeldungen

### Manueller Heartbeat-Test

Sie können einen manuellen Heartbeat-Test durchführen:

```
http://localhost:8080/test-heartbeat
```

### Logs überprüfen

Die Logs enthalten detaillierte Informationen zu API-Anfragen:

```bash
# Allgemeine Logs
tail -f logs/honeypot.log | grep "API"

# Debug-Logs (nur im Debug-Modus)
tail -f logs/debug.log | grep "Heartbeat"

# Fehler-Logs
tail -f logs/error.log
```

## Umgebungsvariablen für die API-Konfiguration

| Variable                | Beschreibung                              | Standard                    |
| ----------------------- | ----------------------------------------- | --------------------------- |
| `API_ENDPOINT`          | Backend-API-URL                           | `http://localhost:3000/api` |
| `API_KEY`               | API-Schlüssel für die Authentifizierung   | -                           |
| `HONEYPOT_ID`           | ID des Honeypots                          | `test`                      |
| `HEARTBEAT_INTERVAL`    | Intervall für Heartbeats in ms            | `60000`                     |
| `HEARTBEAT_RETRY_COUNT` | Anzahl der Wiederholungsversuche          | `3`                         |
| `HEARTBEAT_RETRY_DELAY` | Verzögerung zwischen Wiederholungen in ms | `5000`                      |

## Entwicklungs-Tipps

### Lokaler API-Server für Tests

Für die Entwicklung können Sie einen lokalen Mock-API-Server verwenden:

```javascript
// mockApiServer.js
const express = require("express");
const app = express();
app.use(express.json());

app.post("/api/honeypot/heartbeat", (req, res) => {
  console.log("Heartbeat empfangen:", req.body);
  res.json({ status: "ok", message: "Heartbeat received" });
});

app.post("/api/report", (req, res) => {
  console.log("Angriff gemeldet:", req.body);
  res.json({ status: "ok", message: "Attack reported" });
});

app.get("/api/ping", (req, res) => {
  res.json({ status: "ok", message: "API server is running" });
});

app.listen(3000, () => {
  console.log("Mock API Server läuft auf Port 3000");
});
```

Starten Sie diesen Server und setzen Sie `API_ENDPOINT=http://localhost:3000/api` für lokale Tests.

### Proxy-Konfiguration für Debugging

Mit Tools wie [Postman](https://www.postman.com/) oder [Charles Proxy](https://www.charlesproxy.com/) können Sie die API-Kommunikation zwischen Honeypot und Backend überwachen:

1. Konfigurieren Sie den Proxy in den Umgebungsvariablen:
   ```
   HTTP_PROXY=http://localhost:8888
   HTTPS_PROXY=http://localhost:8888
   ```
2. Starten Sie den Proxy-Server
3. Beobachten Sie den gesamten API-Verkehr für Debugging-Zwecke

## API-Endpunkte

Der Honeypot verwendet folgende API-Endpunkte zur Kommunikation mit dem Backend:

| Endpunkt              | Methode | Beschreibung                                 |
| --------------------- | ------- | -------------------------------------------- |
| `/honeypot/heartbeat` | POST    | Meldet, dass der Honeypot aktiv ist          |
| `/honeypot/report-ip` | POST    | Meldet erkannte Angriffe und verdächtige IPs |
| `/ping`               | GET     | Überprüft, ob das API-Backend erreichbar ist |

### Schema für `/honeypot/report-ip`

```json
{
  "ip_address": "8.8.8.8", // Die zu meldende IP-Adresse (erforderlich)
  "attack_type": "SQL_INJECTION", // Art des Angriffs (optional)
  "description": "SQL-Injection versucht: ' OR 1=1", // Beschreibung (optional)
  "evidence": "{...}" // JSON mit Beweisdaten (optional)
}
```

## Spezifische Fehlerszenarien und Lösungen

### "Request failed with status code 403" bei Angriffsmeldungen

**Symptom:** Der Honeypot meldet "Fehler beim Melden des Angriffs: Request failed with status code 403" in den Logs.

**Ursache:** Dies ist ein Berechtigungsproblem. Der API-Schlüssel hat möglicherweise keine ausreichenden Rechte, um Angriffe zu melden, oder der Honeypot-ID fehlt die Berechtigung.

**Lösungen:**

1. **API-Key überprüfen:** Stellen Sie sicher, dass der verwendete API-Key die richtigen Berechtigungen für die `/report`-Endpunkte hat.

2. **Offline-Modus verwenden:** Wenn Sie temporär keine API-Verbindung herstellen können, starten Sie den Honeypot im Offline-Modus:

   ```bash
   # Start im Offline-Modus
   npm run offline
   # oder
   OFFLINE_MODE=true node src/index.js
   ```

3. **Mock-API verwenden:** Für Tests und Entwicklung können Sie die Mock-API verwenden:

   ```bash
   # Mock-API starten
   npm run mock-api

   # Dann in einem anderen Terminal den Honeypot starten mit:
   API_ENDPOINT=http://localhost:3000/api API_KEY=test-api-key npm run dev
   ```

4. **Angriffsmeldungen manuell senden:** Wenn Sie gespeicherte Angriffe manuell hochladen möchten:

   - Im Debug-Modus: Rufen Sie `http://localhost:8080/upload-offline-attacks` auf
   - Oder verwenden Sie den folgenden Befehl:

   ```bash
   curl -X POST "http://localhost:8080/upload-offline-attacks"
   ```

5. **Berechtigungen im Backend prüfen:** Kontaktieren Sie den API-Administrator, um sicherzustellen, dass:

   - Die Honeypot-ID (${config.honeypotId}) korrekt registriert ist
   - Der API-Schlüssel für diesen Honeypot gültig ist
   - Die Berechtigung für `/report`-Endpunkte erteilt wurde

6. **Lokale Logs überprüfen:** Bei API-Fehlern werden die Angriffe lokal gespeichert in:

   ```
   logs/offline_attacks.json
   ```

7. **API-Anfragen protokollieren:** Bei Bedarf können Sie detaillierte HTTP-Anfragen protokollieren:
   ```bash
   DEBUG=axios NODE_ENV=development npm run dev
   ```
