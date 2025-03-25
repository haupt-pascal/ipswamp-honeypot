/**
 * Mock-API-Server für IPSwamp Honeypot
 *
 * Ein einfacher Server, der die IPSwamp-API simuliert, um lokal zu testen.
 *
 * Verwendung:
 *   node tools/mock-api-server.js
 *
 * Optionen:
 *   --port=3000       Port, auf dem der Server läuft (Standard: 3000)
 *   --fail-rate=0     Prozentsatz der Anfragen, die fehlschlagen sollen (0-100)
 *   --delay=0         Verzögerung in ms für Antworten (simuliert Latenz)
 */

const express = require("express");
const app = express();
const fs = require("fs");
const path = require("path");
const morgan = require("morgan");

// Parsen von Befehlszeilenargumenten
const args = process.argv.slice(2).reduce((acc, arg) => {
  if (arg.startsWith("--")) {
    const [key, value] = arg.slice(2).split("=");
    acc[key] = value || true;
  }
  return acc;
}, {});

// Konfiguration
const config = {
  port: parseInt(args.port || process.env.PORT || "3000"),
  failRate: parseInt(args["fail-rate"] || "0"),
  delay: parseInt(args.delay || "0"),
  requiredApiKey: args["api-key"] || "test-api-key",
  logToFile: args["log-to-file"] || false,
};

// Middleware für JSON-Parsing
app.use(express.json());

// Logging einrichten
if (config.logToFile) {
  const logsDir = path.join(process.cwd(), "logs");
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }

  const accessLogStream = fs.createWriteStream(
    path.join(logsDir, "mock-api-access.log"),
    { flags: "a" }
  );

  app.use(morgan("combined", { stream: accessLogStream }));
}

app.use(morgan("dev"));

// Daten-Speicher
const db = {
  honeypots: {},
  attacks: [],
  requests: [],
};

// Simuliert eine zufällige Verzögerung und möglichen Fehler
function simulateConditions(req, res, next) {
  // Speichere Anfrage für Debug-Zwecke
  db.requests.push({
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    query: req.query,
    body: req.body,
    headers: req.headers,
  });

  // Zufälliger Fehler basierend auf failRate
  const shouldFail = Math.random() * 100 < config.failRate;
  if (shouldFail) {
    console.log("🔴 Simuliere Fehler für Anfrage:", req.path);
    return res.status(500).json({
      error: "Simulierter Serverfehler",
      message: "Diese Anfrage wurde absichtlich zum Scheitern gebracht",
    });
  }

  // API-Key überprüfen
  const apiKey = req.query.api_key;
  if (!apiKey || apiKey !== config.requiredApiKey) {
    console.log("🔑 Ungültiger API-Key:", apiKey);
    return res.status(403).json({
      error: "Forbidden",
      message: "Invalid API key",
    });
  }

  // Verzögerung simulieren
  if (config.delay > 0) {
    return setTimeout(next, config.delay);
  }

  next();
}

// API-Endpunkte

// Basis-Ping-Endpunkt
app.get("/api/ping", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    message: "Mock API Server is running",
  });
});

// Heartbeat
app.post("/api/honeypot/heartbeat", simulateConditions, (req, res) => {
  const { honeypot_id } = req.body;

  if (!honeypot_id) {
    return res.status(400).json({
      error: "Bad Request",
      message: "Missing honeypot_id in request body",
    });
  }

  // Aktualisiere oder erstelle Honeypot-Eintrag
  db.honeypots[honeypot_id] = {
    last_heartbeat: new Date().toISOString(),
    ip_address: req.ip,
    user_agent: req.headers["user-agent"],
  };

  console.log("💓 Heartbeat empfangen von:", honeypot_id);

  res.status(200).json({
    status: "ok",
    message: "Heartbeat received",
    timestamp: new Date().toISOString(),
  });
});

// Angriffsmeldung
app.post("/api/report", simulateConditions, (req, res) => {
  const { ip_address, attack_type, description, evidence, honeypot_id } =
    req.body;

  if (!ip_address || !attack_type) {
    return res.status(400).json({
      error: "Bad Request",
      message: "Missing required fields (ip_address, attack_type)",
    });
  }

  // Füge Angriff zur Liste hinzu
  const attackEntry = {
    id: Date.now().toString(36) + Math.random().toString(36).substr(2),
    ip_address,
    attack_type,
    description,
    evidence,
    honeypot_id: honeypot_id || "unknown",
    reported_at: new Date().toISOString(),
  };

  db.attacks.push(attackEntry);

  console.log(`🔥 Angriff gemeldet: ${attack_type} von ${ip_address}`);

  res.status(200).json({
    status: "ok",
    message: "Attack reported successfully",
    attack_id: attackEntry.id,
  });
});

// IP-Überprüfung
app.get("/api/get", simulateConditions, (req, res) => {
  const { ip } = req.query;

  if (!ip) {
    return res.status(400).json({
      error: "Bad Request",
      message: "Missing IP parameter",
    });
  }

  // Finde alle Angriffe für diese IP
  const attacks = db.attacks.filter((attack) => attack.ip_address === ip);

  res.status(200).json({
    ip,
    attacks_count: attacks.length,
    last_seen:
      attacks.length > 0 ? attacks[attacks.length - 1].reported_at : null,
    attack_types: [...new Set(attacks.map((a) => a.attack_type))],
    is_suspicious: attacks.length > 0,
  });
});

// Admin-Endpunkte für Debug und Tests

// Status des Mock-Servers
app.get("/admin/status", (req, res) => {
  res.json({
    uptime: process.uptime(),
    configuration: config,
    stats: {
      honeypots: Object.keys(db.honeypots).length,
      attacks: db.attacks.length,
      requests: db.requests.length,
    },
    timestamp: new Date().toISOString(),
  });
});

// Alle gemeldeten Angriffe anzeigen
app.get("/admin/attacks", (req, res) => {
  res.json(db.attacks);
});

// Alle Honeypots anzeigen
app.get("/admin/honeypots", (req, res) => {
  res.json(db.honeypots);
});

// Anfragen-History
app.get("/admin/requests", (req, res) => {
  const limit = parseInt(req.query.limit || "50");
  res.json(db.requests.slice(-limit));
});

// Datenbank zurücksetzen
app.post("/admin/reset", (req, res) => {
  db.honeypots = {};
  db.attacks = [];
  db.requests = [];

  res.json({
    status: "ok",
    message: "Database reset successful",
    timestamp: new Date().toISOString(),
  });
});

// Server starten
app.listen(config.port, () => {
  console.log(`
=======================================================
  🌐 IPSwamp Mock API Server läuft auf Port ${config.port}
=======================================================
  
  🛠️  Konfiguration:
  - API-Key: ${config.requiredApiKey}
  - Fehlerrate: ${config.failRate}%
  - Verzögerung: ${config.delay}ms
  
  🔍 Verfügbare Endpunkte:
  - GET  /api/ping
  - POST /api/honeypot/heartbeat
  - POST /api/report
  - GET  /api/get
  
  🧪 Admin-Endpunkte:
  - GET  /admin/status
  - GET  /admin/attacks
  - GET  /admin/honeypots
  - GET  /admin/requests
  - POST /admin/reset
  
  ⚙️  Start mit anderen Einstellungen:
  node tools/mock-api-server.js --port=3000 --fail-rate=20 --delay=500
=======================================================
`);
});
