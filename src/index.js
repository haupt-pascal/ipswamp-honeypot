const express = require("express");
const fs = require("fs");
const path = require("path");
const ip = require("ip");
const { setupHTTPHoneypot } = require("./modules/http-honeypot");
const { setupFTPHoneypot } = require("./modules/ftp-honeypot");
const { setupSSHHoneypot } = require("./modules/ssh-honeypot");
const { setupHTTPSHoneypot } = require("./modules/https-honeypot");
const { setupMailHoneypot } = require("./modules/mail-honeypot");
const { setupMySQLHoneypot } = require("./modules/mysql-honeypot");
const {
  sendHeartbeat,
  reportAttack,
  getLastHeartbeatInfo,
  getReportCacheStats,
  clearStoredAttacks,
} = require("./services/api-service");
const { setupLogger } = require("./utils/logger");

// Setup logger
const logger = setupLogger();

// Create express app
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), "logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Configuration object
const config = {
  honeypotId: process.env.HONEYPOT_ID || "test",
  apiKey:
    process.env.API_KEY ||
    "e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a",
  apiEndpoint: process.env.API_ENDPOINT || "http://localhost:3000/api",
  heartbeatInterval: parseInt(process.env.HEARTBEAT_INTERVAL || "60000"),
  httpPort: parseInt(process.env.HTTP_PORT || "8080"),
  httpsPort: parseInt(process.env.HTTPS_PORT || "8443"),
  sshPort: parseInt(process.env.SSH_PORT || "2222"),
  ftpPort: parseInt(process.env.FTP_PORT || "21"),
  smtpPort: parseInt(process.env.SMTP_PORT || "25"),
  smtpSubmissionPort: parseInt(process.env.SMTP_SUBMISSION_PORT || "587"),
  pop3Port: parseInt(process.env.POP3_PORT || "110"),
  imapPort: parseInt(process.env.IMAP_PORT || "143"),
  mysqlPort: parseInt(process.env.MYSQL_PORT || "3306"),
  hostIP: process.env.HOST_IP || ip.address(),
  debugMode:
    process.env.NODE_ENV === "development" || process.env.DEBUG === "true",
  heartbeatRetryCount: parseInt(process.env.HEARTBEAT_RETRY_COUNT || "3"),
  heartbeatRetryDelay: parseInt(process.env.HEARTBEAT_RETRY_DELAY || "5000"),
  offlineMode: process.env.OFFLINE_MODE === "true", // Add offline mode option
  offlineAttackSync: parseInt(process.env.OFFLINE_ATTACK_SYNC || "300000"), // Sync every 5 minutes by default

  // Module enablement configuration
  enableHTTP: process.env.ENABLE_HTTP !== "false", // Enable by default
  enableHTTPS: process.env.ENABLE_HTTPS === "true",
  enableSSH: process.env.ENABLE_SSH === "true",
  enableFTP: process.env.ENABLE_FTP === "true",
  enableMail: process.env.ENABLE_MAIL === "true",
  enableMySQL: process.env.ENABLE_MYSQL === "true",

  // IP throttling configuration
  maxReportsPerIP: parseInt(process.env.MAX_REPORTS_PER_IP || "5"),
  ipCacheTTL: parseInt(process.env.IP_CACHE_TTL || "3600000"), // 1 hour
  storeThrottledAttacks: process.env.STORE_THROTTLED_ATTACKS === "true",
  reportUniqueTypesOnly: process.env.REPORT_UNIQUE_TYPES_ONLY === "true",
};

logger.info("Honeypot starting up...", {
  honeypotId: config.honeypotId,
  apiEndpoint: config.apiEndpoint,
  hostIP: config.hostIP,
  debugMode: config.debugMode,
  offlineMode: config.offlineMode,
});

// Clear any stored attacks on startup
clearStoredAttacks();
logger.info("Cleared stored attacks on startup");

// Track active honeypot modules
const activeModules = [];

// Setup HTTP honeypot module
if (config.enableHTTP) {
  try {
    setupHTTPHoneypot(app, logger, config, reportAttack);
    activeModules.push({
      name: "http",
      port: config.httpPort,
      status: "running",
    });
  } catch (error) {
    logger.error("Error starting HTTP honeypot", {
      error: error.message,
    });
    activeModules.push({
      name: "http",
      status: "error",
      error: error.message,
    });
  }
}

// Setup SSH honeypot module if enabled
if (config.enableSSH) {
  try {
    const sshServer = setupSSHHoneypot(logger, config, reportAttack);
    activeModules.push({
      name: "ssh",
      port: config.sshPort,
      status: "running",
    });
  } catch (error) {
    logger.error("Error starting SSH honeypot", {
      error: error.message,
    });
    activeModules.push({
      name: "ssh",
      status: "error",
      error: error.message,
    });
  }
}

// Setup FTP honeypot module if enabled
if (config.enableFTP) {
  try {
    const ftpServer = setupFTPHoneypot(logger, config, reportAttack);
    activeModules.push({
      name: "ftp",
      port: config.ftpPort,
      status: "running",
    });
  } catch (error) {
    logger.error("Error starting FTP honeypot", {
      error: error.message,
    });
    activeModules.push({
      name: "ftp",
      status: "error",
      error: error.message,
    });
  }
}

// Setup HTTPS honeypot module if enabled
if (config.enableHTTPS) {
  try {
    setupHTTPSHoneypot(config, logger)
      .then((servers) => {
        activeModules.push({
          name: "https",
          port: config.httpsPort,
          status: "running",
        });
      })
      .catch((error) => {
        logger.error("Error starting HTTPS honeypot", {
          error: error.message,
        });
        activeModules.push({
          name: "https",
          status: "error",
          error: error.message,
        });
      });
  } catch (error) {
    logger.error("Error setting up HTTPS honeypot", {
      error: error.message,
    });
    activeModules.push({
      name: "https",
      status: "error",
      error: error.message,
    });
  }
}

// Setup Mail honeypots (SMTP, POP3, IMAP) if enabled
if (config.enableMail) {
  try {
    setupMailHoneypot(config, logger)
      .then((mailServers) => {
        for (const server of mailServers) {
          activeModules.push({
            name: server.name.toLowerCase(),
            port: server.port,
            status: "running",
          });
        }
      })
      .catch((error) => {
        logger.error("Error starting Mail honeypots", {
          error: error.message,
        });
        activeModules.push({
          name: "mail",
          status: "error",
          error: error.message,
        });
      });
  } catch (error) {
    logger.error("Error setting up Mail honeypots", {
      error: error.message,
    });
    activeModules.push({
      name: "mail",
      status: "error",
      error: error.message,
    });
  }
}

// Setup MySQL honeypot if enabled
if (config.enableMySQL) {
  try {
    setupMySQLHoneypot(config, logger)
      .then((mysqlServers) => {
        activeModules.push({
          name: "mysql",
          port: config.mysqlPort,
          status: "running",
        });
      })
      .catch((error) => {
        logger.error("Error starting MySQL honeypot", {
          error: error.message,
        });
        activeModules.push({
          name: "mysql",
          status: "error",
          error: error.message,
        });
      });
  } catch (error) {
    logger.error("Error setting up MySQL honeypot", {
      error: error.message,
    });
    activeModules.push({
      name: "mysql",
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

  const uptimeString = `${days}d ${hours}h ${minutes}m ${seconds}s`;

  const heartbeatInfo = getLastHeartbeatInfo();
  const lastHeartbeat = heartbeatInfo.response;
  const lastHeartbeatRequest = heartbeatInfo.request;

  // Create a nice status response
  const status = {
    honeypot: {
      id: config.honeypotId,
      version: require("../package.json").version,
      uptime: uptimeString,
      uptimeSeconds: uptime,
      api: {
        endpoint: config.apiEndpoint,
        lastHeartbeat: lastHeartbeat
          ? {
              timestamp: lastHeartbeat.timestamp,
              success: lastHeartbeat.success,
              message: lastHeartbeat.message,
            }
          : null,
        lastRequest: lastHeartbeatRequest,
        offlineMode: config.offlineMode,
      },
      modules: activeModules,
    },
  };

  res.json(status);
});

// API diagnostics endpoint for troubleshooting
app.get("/api-diagnostics", (req, res) => {
  const heartbeatInfo = getLastHeartbeatInfo();
  const cacheStats = getReportCacheStats();

  const diagnostics = {
    config: {
      honeypotId: config.honeypotId,
      apiEndpoint: config.apiEndpoint,
      heartbeatInterval: config.heartbeatInterval,
      offlineMode: config.offlineMode,
    },
    heartbeatInfo: heartbeatInfo,
    reportCacheStats: cacheStats,
    activeModules: activeModules,
  };

  res.json(diagnostics);
});

// Manual heartbeat test
app.get("/test-heartbeat", async (req, res) => {
  try {
    const result = await sendHeartbeat(config, logger);
    res.json({
      success: true,
      message: "Heartbeat sent successfully",
      response: result,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Heartbeat failed",
      error: error.message,
    });
  }
});

// Start server
const server = app.listen(config.httpPort, () => {
  logger.info(`HTTP server started on port ${config.httpPort}`);

  // Start heartbeat interval if not in offline mode
  if (!config.offlineMode) {
    // Initial heartbeat
    sendHeartbeat(config, logger)
      .then(() => {
        logger.info("Initial heartbeat sent successfully");
      })
      .catch((error) => {
        logger.error("Error sending initial heartbeat", {
          error: error.message,
        });
      });

    // Regular heartbeat interval
    setInterval(() => {
      sendHeartbeat(config, logger).catch((error) => {
        logger.error("Error sending heartbeat", {
          error: error.message,
        });
      });
    }, config.heartbeatInterval);
  } else {
    logger.info("Running in offline mode - heartbeat disabled");
  }
});

// Handle shutdown gracefully
process.on("SIGINT", () => {
  logger.info("Shutting down honeypot...");
  server.close(() => {
    logger.info("HTTP server closed");
    process.exit(0);
  });
});

// Export for testing
module.exports = { app, server };
