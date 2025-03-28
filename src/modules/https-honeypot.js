/**
 * HTTPS Management Portal Honeypot Module
 *
 * Simulates a secure admin interface to detect and analyze attacks targeting
 * management interfaces and admin portals.
 */

const express = require("express");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { reportAttack } = require("../services/api-service");

// Setup HTTPS honeypot server
async function setupHTTPSHoneypot(config, logger) {
  // Create Express app
  const app = express();

  // Track suspicious requests
  const suspiciousIPs = new Map();

  // Track login attempts for bruteforce detection
  const loginAttemptTracker = new Map();

  // Create self-signed certificate for HTTPS
  const certPath = path.join(process.cwd(), "logs", "https-cert.pem");
  const keyPath = path.join(process.cwd(), "logs", "https-key.pem");

  // Generate certificates if they don't exist
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    logger.info("Generating self-signed certificate for HTTPS honeypot...");
    generateSelfSignedCert(certPath, keyPath);
  }

  // HTTPS server options
  const httpsOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  };

  // Basic request logging middleware
  app.use((req, res, next) => {
    const clientIP =
      req.headers["x-forwarded-for"] ||
      req.connection.remoteAddress.replace(/^::ffff:/, "");

    // Track client IP activity
    if (!suspiciousIPs.has(clientIP)) {
      suspiciousIPs.set(clientIP, {
        count: 0,
        paths: new Set(),
        userAgents: new Set(),
        firstSeen: Date.now(),
        lastSeen: Date.now(),
      });
    }

    const ipData = suspiciousIPs.get(clientIP);
    ipData.count++;
    ipData.paths.add(req.path);
    ipData.lastSeen = Date.now();

    if (req.headers["user-agent"]) {
      ipData.userAgents.add(req.headers["user-agent"]);
    }

    // Log basic request info
    logger.info(`HTTPS request received: ${req.method} ${req.path}`, {
      ip: clientIP,
      method: req.method,
      path: req.path,
      user_agent: req.headers["user-agent"],
    });

    // Report if this IP is exhibiting suspicious scanning behavior
    // Reduced from 5 to 3 for more sensitive detection
    if (ipData.count >= 3 && ipData.paths.size >= 2) {
      reportHTTPSAttack(config, logger, clientIP, "management_access", {
        request_count: ipData.count,
        paths: Array.from(ipData.paths),
        user_agents: Array.from(ipData.userAgents),
        timespan_seconds: Math.floor((Date.now() - ipData.firstSeen) / 1000),
      });

      // Reset counter after reporting
      ipData.count = 0;
    }

    next();
  });

  // Body parsing middleware
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());

  // Management portal login page
  app.get("/", (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Admin Portal Login</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f7f7f7; }
          .login-container { max-width: 400px; margin: 50px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          h1 { color: #333; text-align: center; }
          input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; box-sizing: border-box; }
          button { width: 100%; padding: 10px; background: #4285f4; color: white; border: none; border-radius: 3px; cursor: pointer; }
          .error { color: red; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="login-container">
          <h1>System Administration</h1>
          <form action="/login" method="post">
            <div>
              <input type="text" name="username" placeholder="Username" required>
            </div>
            <div>
              <input type="password" name="password" placeholder="Password" required>
            </div>
            <button type="submit">Login</button>
          </form>
          <p class="error" id="error"></p>
          <p style="text-align: center; color: #888; font-size: 12px;">Management Portal v3.2.1</p>
        </div>
      </body>
      </html>
    `);
  });

  // Login handler - always fail
  app.post("/login", (req, res) => {
    const clientIP =
      req.headers["x-forwarded-for"] ||
      req.connection.remoteAddress.replace(/^::ffff:/, "");

    const { username, password } = req.body;

    // Log login attempt
    logger.warn(`Login attempt to management portal`, {
      ip: clientIP,
      username: username,
      password_length: password ? password.length : 0,
    });

    // Track login attempts for bruteforce detection
    if (!loginAttemptTracker.has(clientIP)) {
      loginAttemptTracker.set(clientIP, {
        attempts: 1,
        lastAttempt: Date.now(),
        usernames: new Set([username]),
        lastReported: 0,
      });
    } else {
      const tracker = loginAttemptTracker.get(clientIP);
      tracker.attempts++;
      tracker.lastAttempt = Date.now();
      if (username) {
        tracker.usernames.add(username);
      }

      // Report bruteforce attempts after 3 failed logins
      if (tracker.attempts >= 3 && Date.now() - tracker.lastReported > 60000) {
        logger.warn(
          `Possible HTTPS login bruteforce from ${clientIP}: ${tracker.attempts} attempts`,
          {
            ip: clientIP,
            attempts: tracker.attempts,
            usernames: Array.from(tracker.usernames),
          }
        );

        // Report the bruteforce attempt
        reportHTTPSAttack(config, logger, clientIP, "admin_login_bruteforce", {
          attempts: tracker.attempts,
          usernames: Array.from(tracker.usernames),
          last_attempt: new Date().toISOString(),
          path: req.path,
        });

        // Update last reported time
        tracker.lastReported = Date.now();
      }
    }

    // Report login attempt
    reportHTTPSAttack(config, logger, clientIP, "admin_portal_access", {
      username: username,
      password_length: password ? password.length : 0,
      path: req.path,
      method: req.method,
    });

    // Always return failure (after a delay to simulate checking)
    setTimeout(() => {
      res.status(401).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Login Failed</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f7f7f7; }
            .login-container { max-width: 400px; margin: 50px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .error { color: red; margin: 10px 0; text-align: center; }
            a { display: block; text-align: center; margin-top: 20px; color: #4285f4; text-decoration: none; }
          </style>
        </head>
        <body>
          <div class="login-container">
            <h1>Login Failed</h1>
            <p class="error">Invalid username or password.</p>
            <a href="/">Try Again</a>
          </div>
        </body>
        </html>
      `);
    }, 1000);
  });

  // Clean up login tracker periodically to prevent memory leaks
  setInterval(() => {
    const now = Date.now();
    // Clean up trackers older than 1 hour
    for (const [ip, data] of loginAttemptTracker.entries()) {
      if (now - data.lastAttempt > 3600000) {
        // 1 hour
        loginAttemptTracker.delete(ip);
      }
    }
  }, 300000); // Run every 5 minutes

  // Common paths for admin interfaces
  [
    "/admin",
    "/administrator",
    "/adminpanel",
    "/dashboard",
    "/management",
    "/cp",
    "/cpanel",
    "/webadmin",
    "/manage",
    "/system",
    "/control",
    "/maint",
    "/maintenance",
    "/security",
    "/setup",
    "/configure",
    "/wp-admin",
    "/wp-login.php",
    "/admin.php",
    "/joomla/administrator",
    "/server-status",
    "/server-info",
    "/cloudcenter",
    "/jenkins",
    "/phpmyadmin",
    "/mysql",
    "/mariadb",
    "/adminer",
    "/pgadmin",
  ].forEach((path) => {
    app.get(path, (req, res) => {
      const clientIP =
        req.headers["x-forwarded-for"] ||
        req.connection.remoteAddress.replace(/^::ffff:/, "");

      // Report suspicious access attempts
      reportHTTPSAttack(config, logger, clientIP, "admin_portal_access", {
        path: req.path,
        method: req.method,
        user_agent: req.headers["user-agent"] || "None",
      });

      // Redirect to login page
      res.redirect("/");
    });
  });

  // Catch-all for other paths
  app.use((req, res) => {
    const clientIP =
      req.headers["x-forwarded-for"] ||
      req.connection.remoteAddress.replace(/^::ffff:/, "");

    // Report access attempts to unusual paths
    if (req.path !== "/favicon.ico") {
      reportHTTPSAttack(config, logger, clientIP, "suspicious_request", {
        path: req.path,
        method: req.method,
        query: req.query,
        user_agent: req.headers["user-agent"] || "None",
      });
    }

    // Return 404
    res.status(404).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>404 Not Found</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f7f7f7; }
          .container { max-width: 600px; margin: 50px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          h1 { color: #333; text-align: center; }
          p { text-align: center; color: #555; }
          a { display: block; text-align: center; margin-top: 20px; color: #4285f4; text-decoration: none; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>404 Not Found</h1>
          <p>The requested resource could not be found on this server.</p>
          <a href="/">Return to Home</a>
        </div>
      </body>
      </html>
    `);
  });

  // Create HTTPS server
  const server = https.createServer(httpsOptions, app);

  server.listen(config.httpsPort, () => {
    logger.info(`HTTPS honeypot server started on port ${config.httpsPort}`);
  });

  return [
    {
      name: "HTTPS",
      port: config.httpsPort,
      server: server,
    },
  ];
}

// Generate self-signed certificate for HTTPS
function generateSelfSignedCert(certPath, keyPath) {
  // Ensure logs directory exists
  const logsDir = path.dirname(certPath);
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }

  // Generate key and certificate using OpenSSL
  const { execSync } = require("child_process");

  try {
    // Check if OpenSSL is available
    execSync("openssl version");

    // Generate private key
    execSync(`openssl genrsa -out "${keyPath}" 2048`);

    // Generate self-signed certificate
    execSync(
      `openssl req -new -x509 -key "${keyPath}" -out "${certPath}" -days 365 -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"`
    );

    console.log("Self-signed certificate generated successfully.");
  } catch (err) {
    console.error(
      "Failed to generate certificate using OpenSSL. Falling back to internal method."
    );

    // Fallback method if OpenSSL isn't available
    const pki = require("node-forge").pki;

    // Generate a keypair
    const keys = pki.rsa.generateKeyPair(2048);

    // Create a certificate
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1
    );

    // Set subject and issuer
    const attrs = [
      { name: "commonName", value: "localhost" },
      { name: "countryName", value: "US" },
      { shortName: "ST", value: "State" },
      { name: "localityName", value: "City" },
      { name: "organizationName", value: "Organization" },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    // Sign the certificate
    cert.sign(keys.privateKey);

    // Convert to PEM format
    const pemCert = pki.certificateToPem(cert);
    const pemKey = pki.privateKeyToPem(keys.privateKey);

    // Write to files
    fs.writeFileSync(certPath, pemCert);
    fs.writeFileSync(keyPath, pemKey);

    console.log(
      "Self-signed certificate generated successfully using internal method."
    );
  }
}

// Report HTTPS attack to the API
function reportHTTPSAttack(config, logger, ip, attackType, evidence) {
  const attackData = {
    ip_address: ip,
    attack_type: attackType,
    description: `HTTPS management portal ${attackType} detected`,
    evidence: [JSON.stringify(evidence)],
    timestamp: new Date().toISOString(),
  };

  // Report the attack
  reportAttack(config, attackData, logger).catch((error) => {
    logger.error(`Failed to report HTTPS attack: ${error.message}`, {
      ip,
      attack_type: attackType,
    });
  });
}

module.exports = {
  setupHTTPSHoneypot,
};
