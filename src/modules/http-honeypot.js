// HTTP Honeypot Module - Fake web server that catches hackers trying to exploit websites
const express = require("express");

// Common patterns that attackers use - we check for these in requests
const ATTACK_PATTERNS = {
  SQL_INJECTION: [
    "' OR 1=1",
    "1' OR '1'='1",
    "1 OR 1=1",
    "' OR '1'='1",
    "' OR ''='",
    "1' OR '1'='1' --",
    "admin'--",
    "UNION SELECT",
    "SELECT * FROM",
    "DELETE FROM",
    "DROP TABLE",
    "OR 1=1",
  ],
  COMMAND_INJECTION: [
    "; ls -la",
    "& dir",
    "| cat /etc/passwd",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
    "; rm -rf",
    "& del /f",
    "; nc -e /bin/sh",
    "| bash -i",
  ],
  PATH_TRAVERSAL: [
    "../../../",
    "..\\..\\..\\",
    "/etc/passwd",
    "C:\\Windows\\system.ini",
    "WEB-INF/web.xml",
  ],
  XSS: [
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    "eval(",
    "document.cookie",
    "alert(",
    "<img src=x onerror=",
    "String.fromCharCode(",
  ],
  SUSPICIOUS_ENDPOINTS: [
    "/admin",
    "/login",
    "/wp-admin",
    "/phpmyadmin",
    "/manager/html",
    "/.git",
    "/.env",
    "/actuator",
    "/console",
    "/jenkins",
    "/solr",
    "/struts",
    "/weblogic",
  ],
};

// Track login attempts by IP
const loginAttemptTracker = new Map();

// Set up the HTTP honeypot
function setupHTTPHoneypot(app, logger, config, reportAttack) {
  logger.info("Setting up HTTP Honeypot module...");

  // Our own endpoints that shouldn't trigger attack detection
  const SYSTEM_ENDPOINTS = [
    "/monitor",
    "/api-diagnostics",
    "/test-heartbeat",
    "/debug",
  ];

  // Middleware to detect attacks
  app.use((req, res, next) => {
    const clientIP = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    // Skip attack detection for system endpoints
    if (SYSTEM_ENDPOINTS.includes(req.path)) {
      return next();
    }

    // Capture basic info for each request
    const requestInfo = {
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      query: req.query,
      headers: req.headers,
      body: req.body,
      ip: clientIP,
    };

    // Check for suspicious requests
    const attackType = detectAttack(requestInfo);

    if (attackType) {
      logger.warn(`Possible ${attackType} attack detected`, {
        request: requestInfo,
      });

      // Report attack to API
      reportAttack(config, {
        ip_address: clientIP,
        attack_type: attackType,
        description: `Honeypot detected ${attackType} attack: ${req.method} ${req.path}`,
        evidence: JSON.stringify(requestInfo),
      }).catch((error) => {
        logger.error("Error reporting attack", {
          error: error.message,
        });
      });

      // Continue to show the fake server
    }

    // Log all requests for analysis
    logger.info("HTTP request received", { request: requestInfo });
    next();
  });

  // Fake server responses for various endpoints

  // Fake login page
  app.get("/login", (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Admin Login</title>
        </head>
        <body>
          <h1>Login</h1>
          <form method="post" action="/login">
            <div>
              <label>Username:</label>
              <input type="text" name="username" />
            </div>
            <div>
              <label>Password:</label>
              <input type="password" name="password" />
            </div>
            <button type="submit">Login</button>
          </form>
        </body>
      </html>
    `);
  });

  // Fake login post handler
  app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    logger.info("Login attempt", {
      username,
      password: "******",
      ip: clientIP,
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
          `Possible HTTP login bruteforce from ${clientIP}: ${tracker.attempts} attempts`,
          {
            ip: clientIP,
            attempts: tracker.attempts,
            usernames: Array.from(tracker.usernames),
          }
        );

        // Report the bruteforce attempt
        reportAttack(config, {
          ip_address: clientIP,
          attack_type: "LOGIN_BRUTEFORCE",
          description: `HTTP login bruteforce detected: ${tracker.attempts} attempts with ${tracker.usernames.size} unique usernames`,
          evidence: JSON.stringify({
            ip: clientIP,
            attempts: tracker.attempts,
            usernames: Array.from(tracker.usernames),
            timestamp: new Date().toISOString(),
          }),
        }).catch((error) => {
          logger.error("Failed to report HTTP bruteforce", {
            error: error.message,
          });
        });

        // Update last reported time
        tracker.lastReported = Date.now();
      }
    }

    // Report to API - Credential Harvesting
    reportAttack(config, {
      ip_address: clientIP,
      attack_type: "CREDENTIAL_HARVESTING",
      description: `Login attempt with username: ${username}`,
      evidence: JSON.stringify({
        username,
        attempt_time: new Date().toISOString(),
      }),
    }).catch((error) => {
      logger.error("Error reporting login attempt", {
        error: error.message,
      });
    });

    // Always respond with an error
    res.status(401).send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Login Error</title>
        </head>
        <body>
          <h1>Login Error</h1>
          <p>The credentials you entered are invalid. Please try again.</p>
          <a href="/login">Back to Login</a>
        </body>
      </html>
    `);
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

  // Fake admin area
  app.get("/admin", (req, res) => {
    res.status(401).send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Admin Area - Access Denied</title>
        </head>
        <body>
          <h1>Access Denied</h1>
          <p>You must be logged in to access the admin area.</p>
          <a href="/login">Go to Login</a>
        </body>
      </html>
    `);
  });

  // Fake PHP info page
  app.get("/phpinfo.php", (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>PHP Info</title>
        </head>
        <body>
          <h1>PHP Version 7.4.3</h1>
          <table>
            <tr><td>System</td><td>Linux honeypot 5.15.0-1039 #46-Ubuntu SMP x86_64</td></tr>
            <tr><td>PHP Version</td><td>7.4.3</td></tr>
            <tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
            <tr><td>Document Root</td><td>/var/www/html</td></tr>
          </table>
        </body>
      </html>
    `);
  });

  // Fake API endpoint
  app.get("/api/users", (req, res) => {
    res.status(401).json({
      error: "Unauthorized",
      message: "Valid API key required",
    });
  });

  // 404 handler for all other requests
  app.use((req, res, next) => {
    // Skip system routes
    if (
      req.path === "/monitor" ||
      req.path === "/debug" ||
      req.path === "/api-diagnostics" ||
      req.path === "/test-heartbeat"
    ) {
      return next();
    }

    res.status(404).send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>404 - Page Not Found</title>
        </head>
        <body>
          <h1>404 - Page Not Found</h1>
          <p>The requested page could not be found.</p>
        </body>
      </html>
    `);
  });

  logger.info("HTTP Honeypot module successfully set up.");
}

// Function to detect attacks
function detectAttack(requestInfo) {
  const { method, path, query, headers, body } = requestInfo;

  // Check suspicious paths
  for (const endpoint of ATTACK_PATTERNS.SUSPICIOUS_ENDPOINTS) {
    if (path.includes(endpoint)) {
      return "SUSPICIOUS_ENDPOINT";
    }
  }

  // Check URL parameters for attack patterns
  const queryString = Object.values(query || {}).join(" ");

  // SQL injection in query parameters
  if (
    ATTACK_PATTERNS.SQL_INJECTION.some((pattern) =>
      queryString.includes(pattern)
    )
  ) {
    return "SQL_INJECTION";
  }

  // Command injection in query parameters
  if (
    ATTACK_PATTERNS.COMMAND_INJECTION.some((pattern) =>
      queryString.includes(pattern)
    )
  ) {
    return "COMMAND_INJECTION";
  }

  // XSS in query parameters
  if (ATTACK_PATTERNS.XSS.some((pattern) => queryString.includes(pattern))) {
    return "XSS";
  }

  // Path traversal in query parameters
  if (
    ATTACK_PATTERNS.PATH_TRAVERSAL.some((pattern) =>
      queryString.includes(pattern)
    )
  ) {
    return "PATH_TRAVERSAL";
  }

  // Check request body if present
  if (body && typeof body === "object") {
    const bodyString = JSON.stringify(body);

    // SQL injection in body
    if (
      ATTACK_PATTERNS.SQL_INJECTION.some((pattern) =>
        bodyString.includes(pattern)
      )
    ) {
      return "SQL_INJECTION";
    }

    // Command injection in body
    if (
      ATTACK_PATTERNS.COMMAND_INJECTION.some((pattern) =>
        bodyString.includes(pattern)
      )
    ) {
      return "COMMAND_INJECTION";
    }

    // XSS in body
    if (ATTACK_PATTERNS.XSS.some((pattern) => bodyString.includes(pattern))) {
      return "XSS";
    }
  }

  // Check for suspicious user agents
  const userAgent = headers["user-agent"] || "";

  // More specific detection for suspicious user agents
  // Avoid flagging regular curl usage for monitoring tools
  const suspiciousUserAgents = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "gobuster",
    "dirbuster",
  ];

  if (
    suspiciousUserAgents.some((agent) =>
      userAgent.toLowerCase().includes(agent)
    )
  ) {
    return "SUSPICIOUS_USER_AGENT";
  }

  // No known attack patterns detected
  return null;
}

module.exports = { setupHTTPHoneypot };
