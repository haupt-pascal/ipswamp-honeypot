// FTP Honeypot Module - Simulates an FTP server to catch sneaky attackers
const ftpd = require("ftpd");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// Default FTP user accounts - super basic creds that attackers try
const FTP_USERS = {
  anonymous: { password: "", root: "./ftp" },
  admin: { password: "admin123", root: "./ftp" },
  user: { password: "password123", root: "./ftp" },
  ftpuser: { password: "ftp123", root: "./ftp" },
};

// Track auth attempts to catch brute forcers
const authAttemptTracker = new Map();

/**
 * Sets up the FTP honeypot server
 * @param {Object} logger - Winston logger instance
 * @param {Object} config - Honeypot config
 * @param {Function} reportAttack - Function to report attacks to API
 * @returns {Object} FTP server instance
 */
function setupFTPHoneypot(logger, config, reportAttack) {
  logger.info("Setting up FTP Honeypot module...");

  // Create FTP dir if it doesn't exist
  const ftpRoot = path.join(process.cwd(), "ftp");
  if (!fs.existsSync(ftpRoot)) {
    fs.mkdirSync(ftpRoot, { recursive: true });

    // Create some bait files
    fs.writeFileSync(
      path.join(ftpRoot, "README.txt"),
      "This is a test FTP server."
    );
    fs.writeFileSync(
      path.join(ftpRoot, "welcome.txt"),
      "Welcome to our FTP server!"
    );

    // Create a "private" folder as bait
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

  // FTP server options
  const options = {
    host: "0.0.0.0",
    port: parseInt(process.env.FTP_PORT || "21"),
    tls: null, // No TLS for honeypot (could add for secure FTP)
  };

  // Create FTP server
  const server = new ftpd.FtpServer(options.host, {
    getInitialCwd: () => "/",
    getRoot: (username) => FTP_USERS[username]?.root || ftpRoot,
    pasvPortRangeStart: 1025,
    pasvPortRangeEnd: 1050,
    tlsOptions: options.tls,
    allowUnauthorizedTls: true,
    useWriteFile: false,
    useReadFile: false,
    uploadMaxSlurpSize: 1024, // 1KB - don't allow big uploads
  });

  // Track connections
  const connections = new Map();

  // Server events
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

    logger.info("FTP connection established", {
      clientId: clientInfo.id,
      ip: clientInfo.ip,
      port: clientInfo.port,
    });

    // Login event
    connection.on("command:user", (username, success) => {
      clientInfo.username = username;
      logger.info("FTP username received", {
        clientId: clientInfo.id,
        username,
      });
    });

    // Password event - Track attempts for bruteforce detection
    connection.on("command:pass", (password, success) => {
      logger.info("FTP login attempt", {
        clientId: clientInfo.id,
        username: clientInfo.username,
        success,
      });

      // Track auth attempts by IP for bruteforce detection
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

      // Report the login attempt to the API
      reportAttack(config, {
        ip_address: clientInfo.ip,
        attack_type: "FTP_LOGIN_ATTEMPT",
        description: `FTP login attempt: User: ${clientInfo.username}, Success: ${success}`,
        evidence: JSON.stringify({
          username: clientInfo.username,
          success,
          timestamp: new Date().toISOString(),
        }),
      }).catch((error) => {
        logger.error("Error reporting FTP login attempt", {
          error: error.message,
        });
      });

      if (success) {
        clientInfo.authenticated = true;
      }
    });

    // Command tracking
    connection.on("command:*", (command, parameters) => {
      clientInfo.commands.push({
        command,
        parameters,
        time: new Date(),
      });

      logger.info("FTP command received", {
        clientId: clientInfo.id,
        command,
        parameters,
      });

      // Report certain suspicious commands (e.g., DELE, STOR in sensitive directories)
      const suspiciousCommands = ["DELE", "RMD", "STOR", "SITE"];
      if (suspiciousCommands.includes(command)) {
        reportAttack(config, {
          ip_address: clientInfo.ip,
          attack_type: "FTP_SUSPICIOUS_COMMAND",
          description: `Suspicious FTP command: ${command} ${parameters}`,
          evidence: JSON.stringify({
            clientId: clientInfo.id,
            username: clientInfo.username,
            command,
            parameters,
            authenticated: clientInfo.authenticated,
            timestamp: new Date().toISOString(),
          }),
        }).catch((error) => {
          logger.error("Error reporting suspicious FTP command", {
            error: error.message,
          });
        });
      }
    });

    // Connection end
    connection.on("close", () => {
      if (connections.has(clientInfo.id)) {
        const sessionInfo = connections.get(clientInfo.id);
        const duration = (new Date() - sessionInfo.startTime) / 1000;

        logger.info("FTP connection closed", {
          clientId: clientInfo.id,
          ip: clientInfo.ip,
          duration: `${duration.toFixed(2)}s`,
          commandCount: sessionInfo.commands.length,
        });

        connections.delete(clientInfo.id);
      }
    });

    // Authentication logic
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

  // Start server
  server.debugging = process.env.NODE_ENV !== "production";
  server.listen(options.port);

  logger.info(`FTP Honeypot started on port ${options.port}`);

  return server;
}

module.exports = { setupFTPHoneypot };
