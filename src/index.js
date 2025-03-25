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

const {
  sendHeartbeat,
  reportAttack,
  testApiConnection,
  getLastHeartbeatInfo,
  uploadStoredAttacks,
} = require("./services/api-service");
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
  heartbeatRetryCount: parseInt(process.env.HEARTBEAT_RETRY_COUNT || "3"),
  heartbeatRetryDelay: parseInt(process.env.HEARTBEAT_RETRY_DELAY || "5000"),
  offlineMode: process.env.OFFLINE_MODE === "true", // Add offline mode option
  offlineAttackSync: parseInt(process.env.OFFLINE_ATTACK_SYNC || "300000"), // Sync every 5 minutes by default
};

// Logger einrichten
const logger = setupLogger();

// Express-App erstellen
const app = express();

// Middleware für JSON-Parsing
app.use(express.json());

// Status des letzten Heartbeats
let lastHeartbeatSuccess = null;
let consecutiveHeartbeatFailures = 0;

// Heartbeat-Funktion einrichten
async function performHeartbeat() {
  try {
    logger.info("Sende Heartbeat an API-Server...");
    const response = await sendHeartbeat(config, logger);
    logger.info("Heartbeat erfolgreich gesendet", { response });

    // Erfolgreicher Heartbeat, setze Fehler-Counter zurück
    lastHeartbeatSuccess = new Date().toISOString();
    consecutiveHeartbeatFailures = 0;
  } catch (error) {
    consecutiveHeartbeatFailures++;

    logger.error(
      `Fehler beim Senden des Heartbeats (Versuch ${consecutiveHeartbeatFailures})`,
      {
        error: error.message,
        statusCode: error.response?.status,
        responseData: error.response?.data,
      }
    );

    // Bei 403 Forbidden, könnte es ein API-Key-Problem sein
    if (error.response && error.response.status === 403) {
      logger.warn("403 Forbidden - Überprüfe API-Key und Berechtigungen", {
        apiEndpoint: config.apiEndpoint,
        honeypotId: config.honeypotId,
        // Zeige verkürzte Version des API-Keys für Debug-Zwecke
        apiKeyPrefix: config.apiKey.substring(0, 8) + "...",
      });
    }

    // Bei mehreren aufeinanderfolgenden Fehlern, versuche eine Wiederholung
    if (
      config.debugMode &&
      consecutiveHeartbeatFailures <= config.heartbeatRetryCount
    ) {
      logger.info(
        `Versuche Heartbeat erneut in ${
          config.heartbeatRetryDelay / 1000
        } Sekunden...`
      );

      // Sofortiger erneuter Versuch im Debug-Modus
      setTimeout(async () => {
        try {
          logger.debug("Erneuter Heartbeat-Versuch nach Fehler...");
          await sendHeartbeat(config, logger);
          logger.info("Erneuter Heartbeat-Versuch erfolgreich");
          lastHeartbeatSuccess = new Date().toISOString();
          consecutiveHeartbeatFailures = 0;
        } catch (retryError) {
          logger.error("Auch erneuter Heartbeat-Versuch fehlgeschlagen", {
            error: retryError.message,
          });
        }
      }, config.heartbeatRetryDelay);
    }

    // Bei anhaltenden Fehlern, teste die API-Verbindung
    if (consecutiveHeartbeatFailures === 3) {
      logger.warn("Mehrere Heartbeat-Fehler - teste API-Verbindung...");
      testApiConnection(config, logger).then((result) => {
        if (!result.success) {
          logger.error(
            "API-Verbindung fehlgeschlagen - möglicherweise Server-Problem"
          );
        }
      });
    }
  }
}

// Heartbeat beim Start ausführen - mit kurzer Verzögerung
setTimeout(() => {
  performHeartbeat();
}, 2000);

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

// Make sure this route comes AFTER setting up the HTTP honeypot
// but BEFORE the 404 handler in http-honeypot.js
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
    heartbeat: {
      lastSuccess: lastHeartbeatSuccess,
      consecutiveFailures: consecutiveHeartbeatFailures,
      status: lastHeartbeatSuccess
        ? consecutiveHeartbeatFailures > 0
          ? "warning"
          : "ok"
        : "error",
    },
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

// Modified reportAttack wrapper to handle errors gracefully
function safeReportAttack(attackData) {
  reportAttack(config, attackData, logger).catch((error) => {
    // Already logged inside reportAttack function
    if (consecutiveReportFailures++ === 0) {
      logger.warn(
        "API-Verbindungsprobleme: Weitere Angriffe werden nur lokal gespeichert",
        {
          honeypotId: config.honeypotId,
        }
      );
    }
  });
}

// Track report failures
let consecutiveReportFailures = 0;

// Offline attack sync job
if (!config.offlineMode) {
  const syncJob = new CronJob("*/5 * * * *", async () => {
    if (consecutiveReportFailures > 0) {
      logger.info(
        "Versuche offline gespeicherte Angriffe zu synchronisieren..."
      );
      try {
        const result = await uploadStoredAttacks(config, logger);
        if (result.uploaded > 0) {
          logger.info(
            `${result.uploaded} Angriffe erfolgreich synchronisiert, ${
              result.remaining || 0
            } verbleibend`
          );
          if (result.remaining === 0) {
            consecutiveReportFailures = 0;
          }
        }
      } catch (error) {
        logger.error("Fehler bei der Angriffs-Synchronisation", {
          error: error.message,
        });
      }
    }
  });
  syncJob.start();
}

// Debug-Endpunkt für Entwicklung und Tests
if (config.debugMode) {
  app.get("/debug", (req, res) => {
    // Diese Route nur im Debug-Modus verfügbar machen
    res.status(200).json({
      activeModules,
      lastRequests: [], // Hier könnten die letzten Anfragen angezeigt werden
      config: {
        ...config,
        apiKey: "***redacted***", // API-Key nicht anzeigen
      },
      environment: process.env,
      heartbeatInfo: getLastHeartbeatInfo(),
    });
  });

  // API-Diagnose-Endpunkt
  app.get("/api-diagnostics", async (req, res) => {
    // Führe API-Verbindungstest durch
    const testResult = await testApiConnection(config, logger);

    // Stelle Diagnoseinformationen bereit
    res.status(200).json({
      apiEndpoint: config.apiEndpoint,
      honeypotId: config.honeypotId,
      heartbeat: {
        lastSuccess: lastHeartbeatSuccess,
        consecutiveFailures: consecutiveHeartbeatFailures,
        status: lastHeartbeatSuccess
          ? consecutiveHeartbeatFailures > 0
            ? "warning"
            : "ok"
          : "error",
      },
      connectionTest: testResult,
      lastHeartbeat: getLastHeartbeatInfo(),
    });
  });

  // Heartbeat-Test-Endpunkt
  app.get("/test-heartbeat", async (req, res) => {
    try {
      logger.debug("Manueller Heartbeat-Test gestartet...");
      const result = await sendHeartbeat(config, logger);
      res.status(200).json({
        success: true,
        message: "Heartbeat erfolgreich gesendet",
        result,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: "Heartbeat fehlgeschlagen",
        error: error.message,
        response: error.response
          ? {
              status: error.response.status,
              data: error.response.data,
            }
          : null,
        timestamp: new Date().toISOString(),
      });
    }
  });

  // Offline attacks management endpoint
  app.get("/offline-attacks", async (req, res) => {
    const fs = require("fs");
    const path = require("path");

    const offlineAttacksFile = path.join(
      process.cwd(),
      "logs",
      "offline_attacks.json"
    );

    if (!fs.existsSync(offlineAttacksFile)) {
      return res.json({ attacks: [], count: 0 });
    }

    try {
      const content = fs.readFileSync(offlineAttacksFile, "utf8");
      const attacks = JSON.parse(content);
      res.json({
        attacks,
        count: attacks.length,
        pending: attacks.filter((a) => a.pending_upload).length,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post("/upload-offline-attacks", async (req, res) => {
    try {
      const result = await uploadStoredAttacks(config, logger);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  logger.info("Debug-Modus aktiviert. Debug-Endpunkte verfügbar.");
}

// Server starten
app.listen(config.httpPort, () => {
  logger.info(`Honeypot-Server gestartet auf Port ${config.httpPort}`);
  logger.info(
    `Konfiguration: ${JSON.stringify(
      {
        ...config,
        apiKey: "***redacted***", // API-Key aus Logs entfernen
      },
      null,
      2
    )}`
  );
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
