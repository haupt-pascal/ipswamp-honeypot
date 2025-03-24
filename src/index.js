// Hauptdatei des Honeypot-Services
const express = require("express");
const winston = require("winston");
const { CronJob } = require("cron");
const ip = require("ip");

// Module importieren
const { setupHTTPHoneypot } = require("./modules/http-honeypot");
const { setupSSHHoneypot } = require("./modules/ssh-honeypot");
// Neues FTP-Modul importieren (optional)
let setupFTPHoneypot;
try {
  setupFTPHoneypot = require("./modules/ftp-honeypot").setupFTPHoneypot;
} catch (error) {
  // Das Modul ist optional und kann fehlen
  console.warn(
    "FTP-Honeypot-Modul konnte nicht geladen werden:",
    error.message
  );
}

const { sendHeartbeat, reportAttack } = require("./services/api-service");
const { setupLogger } = require("./utils/logger");

// Konfiguration laden
const config = {
  honeypotId: process.env.HONEYPOT_ID || "test",
  apiKey:
    process.env.API_KEY ||
    "e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a",
  apiEndpoint: process.env.API_ENDPOINT || "http://localhost:3000/api",
  heartbeatInterval: parseInt(process.env.HEARTBEAT_INTERVAL || "60000"),
  httpPort: parseInt(process.env.HTTP_PORT || "8080"),
  hostIP: process.env.HOST_IP || ip.address(),
  debugMode:
    process.env.NODE_ENV === "development" || process.env.DEBUG === "true",
};

// Logger einrichten
const logger = setupLogger();

// Express-App erstellen
const app = express();

// Middleware für JSON-Parsing
app.use(express.json());

// Heartbeat-Funktion einrichten
async function performHeartbeat() {
  try {
    logger.info("Sende Heartbeat an API-Server...");
    const response = await sendHeartbeat(config);
    logger.info("Heartbeat erfolgreich gesendet", { response });
  } catch (error) {
    logger.error("Fehler beim Senden des Heartbeats", { error: error.message });
  }
}

// Heartbeat beim Start ausführen
performHeartbeat();

// Cron-Job für regelmäßige Heartbeats einrichten (jede Minute)
const heartbeatJob = new CronJob("* * * * *", performHeartbeat);
heartbeatJob.start();

// Aktive Module verfolgen
const activeModules = [];

// Haupt-Honeypot-Module einrichten
setupHTTPHoneypot(app, logger, config, reportAttack);
activeModules.push({
  name: "http",
  port: config.httpPort,
  status: "running",
});

// SSH-Honeypot einrichten
try {
  const sshPort = parseInt(process.env.SSH_PORT || "2222");
  const sshServer = setupSSHHoneypot(logger, config, reportAttack);
  activeModules.push({
    name: "ssh",
    port: sshPort,
    status: "running",
  });
} catch (error) {
  logger.error("Fehler beim Starten des SSH-Honeypots", {
    error: error.message,
  });
  activeModules.push({
    name: "ssh",
    status: "error",
    error: error.message,
  });
}

// FTP-Honeypot einrichten (wenn verfügbar)
if (setupFTPHoneypot) {
  try {
    const ftpPort = parseInt(process.env.FTP_PORT || "21");
    const ftpServer = setupFTPHoneypot(logger, config, reportAttack);
    activeModules.push({
      name: "ftp",
      port: ftpPort,
      status: "running",
    });
  } catch (error) {
    logger.error("Fehler beim Starten des FTP-Honeypots", {
      error: error.message,
    });
    activeModules.push({
      name: "ftp",
      status: "error",
      error: error.message,
    });
  }
}

// Füge eine verbesserte Monitoring-Route hinzu
app.get("/monitor", (req, res) => {
  const uptime = process.uptime();
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  const seconds = Math.floor(uptime % 60);

  const formattedUptime = `${days}d ${hours}h ${minutes}m ${seconds}s`;

  const memoryUsage = process.memoryUsage();

  res.status(200).json({
    status: "running",
    honeypotId: config.honeypotId,
    modules: activeModules,
    uptime: formattedUptime,
    uptimeSeconds: uptime,
    memoryUsage: {
      rss: `${Math.round(memoryUsage.rss / 1024 / 1024)} MB`,
      heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)} MB`,
      heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)} MB`,
    },
    system: {
      nodeVersion: process.version,
      platform: process.platform,
      hostname: require("os").hostname(),
    },
    config: config.debugMode
      ? {
          honeypotId: config.honeypotId,
          apiEndpoint: config.apiEndpoint,
          hostIP: config.hostIP,
          httpPort: config.httpPort,
          debugMode: config.debugMode,
        }
      : "Debug-Informationen deaktiviert",
  });
});

// Debug-Endpunkt für Entwicklung und Tests
if (config.debugMode) {
  app.get("/debug", (req, res) => {
    // Diese Route nur im Debug-Modus verfügbar machen
    res.status(200).json({
      activeModules,
      lastRequests: [], // Hier könnten die letzten Anfragen angezeigt werden
      config,
      environment: process.env,
    });
  });

  logger.info("Debug-Modus aktiviert. /debug Endpunkt verfügbar.");
}

// Server starten
app.listen(config.httpPort, () => {
  logger.info(`Honeypot-Server gestartet auf Port ${config.httpPort}`);
  logger.info(`Konfiguration: ${JSON.stringify(config, null, 2)}`);
});

// Graceful Shutdown
process.on("SIGTERM", () => {
  logger.info("SIGTERM Signal empfangen. Beende Anwendung...");
  heartbeatJob.stop();
  process.exit(0);
});

process.on("SIGINT", () => {
  logger.info("SIGINT Signal empfangen. Beende Anwendung...");
  heartbeatJob.stop();
  process.exit(0);
});
