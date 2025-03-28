// FTP-Honeypot-Modul
const ftpd = require("ftpd");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// FTP-Konfiguration
const FTP_USERS = {
  anonymous: { password: "", root: "./ftp" },
  admin: { password: "admin123", root: "./ftp" },
  user: { password: "password123", root: "./ftp" },
  ftpuser: { password: "ftp123", root: "./ftp" },
};

// Track authentication attempts by IP
const authAttemptTracker = new Map();

/**
 * Erstellt ein FTP-Honeypot-Modul
 * @param {Object} logger - Winston Logger-Instanz
 * @param {Object} config - Konfiguration des Honeypots
 * @param {Function} reportAttack - Funktion zum Melden von Angriffen
 * @returns {Object} FTP-Server-Instanz
 */
function setupFTPHoneypot(logger, config, reportAttack) {
  logger.info("FTP-Honeypot-Modul wird eingerichtet...");

  // FTP-Verzeichnis erstellen, falls es nicht existiert
  const ftpRoot = path.join(process.cwd(), "ftp");
  if (!fs.existsSync(ftpRoot)) {
    fs.mkdirSync(ftpRoot, { recursive: true });

    // Einige Demo-Dateien erstellen
    fs.writeFileSync(
      path.join(ftpRoot, "README.txt"),
      "This is a test FTP server."
    );
    fs.writeFileSync(
      path.join(ftpRoot, "welcome.txt"),
      "Welcome to our FTP server!"
    );

    // Einen "private" Ordner erstellen als Köder
    const privateDir = path.join(ftpRoot, "private");
    fs.mkdirSync(privateDir, { recursive: true });
    fs.writeFileSync(
      path.join(privateDir, "users.txt"),
      "admin:admin123\nroot:password123\nuser:user123"
    );
    fs.writeFileSync(
      path.join(privateDir, "config.json"),
      JSON.stringify(
        {
          database: {
            host: "localhost",
            username: "dbadmin",
            password: "dbpass123",
          },
          api_keys: ["k8dj3n9s7", "j29sk39dm2", "k2j3n4k5j6"],
        },
        null,
        2
      )
    );
  }

  // FTP-Server-Optionen
  const options = {
    host: "0.0.0.0",
    port: parseInt(process.env.FTP_PORT || "21"),
    tls: null, // Kein TLS für Honeypot (kann für sicheres FTP hinzugefügt werden)
  };

  // FTP-Server erstellen
  const server = new ftpd.FtpServer(options.host, {
    getInitialCwd: () => "/",
    getRoot: (username) => FTP_USERS[username]?.root || ftpRoot,
    pasvPortRangeStart: 1025,
    pasvPortRangeEnd: 1050,
    tlsOptions: options.tls,
    allowUnauthorizedTls: true,
    useWriteFile: false,
    useReadFile: false,
    uploadMaxSlurpSize: 1024, // 1KB - keine großen Uploads erlauben
  });

  // Verbindungen verfolgen
  const connections = new Map();

  // Server-Events
  server.on("client:connected", (connection) => {
    const clientInfo = {
      id: crypto.randomBytes(8).toString("hex"),
      ip: connection.socket.remoteAddress,
      port: connection.socket.remotePort,
      commands: [],
      username: null,
      authenticated: false,
      startTime: new Date(),
    };

    connections.set(clientInfo.id, clientInfo);

    logger.info("FTP-Verbindung hergestellt", {
      clientId: clientInfo.id,
      ip: clientInfo.ip,
      port: clientInfo.port,
    });

    // Login-Event
    connection.on("command:user", (username, success) => {
      clientInfo.username = username;
      logger.info("FTP-Benutzername empfangen", {
        clientId: clientInfo.id,
        username,
      });
    });

    // Passwort-Event - Track attempts for bruteforce detection
    connection.on("command:pass", (password, success) => {
      logger.info("FTP-Anmeldungsversuch", {
        clientId: clientInfo.id,
        username: clientInfo.username,
        success,
      });

      // Track authentication attempts by IP for bruteforce detection
      if (!authAttemptTracker.has(clientInfo.ip)) {
        authAttemptTracker.set(clientInfo.ip, {
          attempts: 1,
          lastAttempt: Date.now(),
          usernames: new Set([clientInfo.username || "anonymous"]),
          lastReported: 0,
        });
      } else {
        const tracker = authAttemptTracker.get(clientInfo.ip);
        tracker.attempts++;
        tracker.lastAttempt = Date.now();
        if (clientInfo.username) {
          tracker.usernames.add(clientInfo.username);
        }

        // Report bruteforce attempts after 3 failed logins
        if (
          tracker.attempts >= 3 &&
          Date.now() - tracker.lastReported > 60000
        ) {
          logger.warn(
            `Possible FTP bruteforce from ${clientInfo.ip}: ${tracker.attempts} attempts`,
            {
              ip: clientInfo.ip,
              attempts: tracker.attempts,
              usernames: Array.from(tracker.usernames),
            }
          );

          // Report the bruteforce attempt
          reportAttack(config, {
            ip_address: clientInfo.ip,
            attack_type: "FTP_BRUTEFORCE",
            description: `FTP bruteforce detected: ${tracker.attempts} attempts with ${tracker.usernames.size} unique usernames`,
            evidence: JSON.stringify({
              ip: clientInfo.ip,
              attempts: tracker.attempts,
              usernames: Array.from(tracker.usernames),
              timestamp: new Date().toISOString(),
            }),
          }).catch((error) => {
            logger.error("Failed to report FTP bruteforce", {
              error: error.message,
            });
          });

          // Update last reported time
          tracker.lastReported = Date.now();
        }
      }

      // Melde den Anmeldungsversuch an die API
      reportAttack(config, {
        ip_address: clientInfo.ip,
        attack_type: "FTP_LOGIN_ATTEMPT",
        description: `FTP-Anmeldungsversuch: Benutzer: ${clientInfo.username}, Erfolg: ${success}`,
        evidence: JSON.stringify({
          username: clientInfo.username,
          success,
          timestamp: new Date().toISOString(),
        }),
      }).catch((error) => {
        logger.error("Fehler beim Melden des FTP-Anmeldungsversuchs", {
          error: error.message,
        });
      });

      if (success) {
        clientInfo.authenticated = true;
      }
    });

    // Befehls-Tracking
    connection.on("command:*", (command, parameters) => {
      clientInfo.commands.push({
        command,
        parameters,
        time: new Date(),
      });

      logger.info("FTP-Befehl empfangen", {
        clientId: clientInfo.id,
        command,
        parameters,
      });

      // Bestimmte verdächtige Befehle melden (z.B. DELE, STOR in sensiblen Verzeichnissen)
      const suspiciousCommands = ["DELE", "RMD", "STOR", "SITE"];
      if (suspiciousCommands.includes(command)) {
        reportAttack(config, {
          ip_address: clientInfo.ip,
          attack_type: "FTP_SUSPICIOUS_COMMAND",
          description: `Verdächtiger FTP-Befehl: ${command} ${parameters}`,
          evidence: JSON.stringify({
            clientId: clientInfo.id,
            username: clientInfo.username,
            command,
            parameters,
            authenticated: clientInfo.authenticated,
            timestamp: new Date().toISOString(),
          }),
        }).catch((error) => {
          logger.error("Fehler beim Melden des verdächtigen FTP-Befehls", {
            error: error.message,
          });
        });
      }
    });

    // Verbindungs-Ende
    connection.on("close", () => {
      if (connections.has(clientInfo.id)) {
        const sessionInfo = connections.get(clientInfo.id);
        const duration = (new Date() - sessionInfo.startTime) / 1000;

        logger.info("FTP-Verbindung geschlossen", {
          clientId: clientInfo.id,
          ip: clientInfo.ip,
          duration: `${duration.toFixed(2)}s`,
          commandCount: sessionInfo.commands.length,
        });

        connections.delete(clientInfo.id);
      }
    });

    // Authentifizierungslogik
    connection.on("command:pass", (password) => {
      const username = clientInfo.username;

      if (FTP_USERS[username] && FTP_USERS[username].password === password) {
        connection.username = username;
        connection.authenticated = true;
        connection.reply(230, "Login successful");
      } else {
        connection.reply(530, "Authentication failed");
      }
    });
  });

  // Clean up auth tracker periodically to prevent memory leaks
  setInterval(() => {
    const now = Date.now();
    // Clean up trackers older than 1 hour
    for (const [ip, data] of authAttemptTracker.entries()) {
      if (now - data.lastAttempt > 3600000) {
        // 1 hour
        authAttemptTracker.delete(ip);
      }
    }
  }, 300000); // Run every 5 minutes

  // Server starten
  server.debugging = process.env.NODE_ENV !== "production";
  server.listen(options.port);

  logger.info(`FTP-Honeypot gestartet auf Port ${options.port}`);

  return server;
}

module.exports = { setupFTPHoneypot };
