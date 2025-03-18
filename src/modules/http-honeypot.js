// HTTP-Honeypot-Modul
const express = require('express');

// Typische Angriffsmuster für HTTP-Requests
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
    "OR 1=1"
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
    "| bash -i"
  ],
  PATH_TRAVERSAL: [
    "../../../",
    "..\\..\\..\\",
    "/etc/passwd",
    "C:\\Windows\\system.ini",
    "WEB-INF/web.xml"
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
    "String.fromCharCode("
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
    "/weblogic"
  ]
};

// HTTP-Honeypot einrichten
function setupHTTPHoneypot(app, logger, config, reportAttack) {
  logger.info('HTTP-Honeypot-Modul wird eingerichtet...');

  // Middleware für die Erkennung von Angriffen
  app.use((req, res, next) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // Erfassen von Grundinformationen für jede Anfrage
    const requestInfo = {
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      query: req.query,
      headers: req.headers,
      body: req.body,
      ip: clientIP
    };

    // Überprüfen auf verdächtige Anfragen
    const attackType = detectAttack(requestInfo);
    
    if (attackType) {
      logger.warn(`Möglicher ${attackType}-Angriff erkannt`, { request: requestInfo });
      
      // Angriff an API melden
      reportAttack(config, {
        ip_address: clientIP,
        attack_type: attackType,
        description: `Honeypot hat einen ${attackType}-Angriff erkannt: ${req.method} ${req.path}`,
        evidence: JSON.stringify(requestInfo)
      }).catch(error => {
        logger.error('Fehler beim Melden des Angriffs', { error: error.message });
      });

      // Weitermachen, um den fake server zu presentieren
    }

    // Aufzeichnen aller Anfragen für Analysezwecke
    logger.info('HTTP-Anfrage empfangen', { request: requestInfo });
    next();
  });

  // Fake-Server-Antworten für verschiedene Endpunkte

  // Fake-Login-Seite
  app.get('/login', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Administrations-Login</title>
        </head>
        <body>
          <h1>Login</h1>
          <form method="post" action="/login">
            <div>
              <label>Benutzername:</label>
              <input type="text" name="username" />
            </div>
            <div>
              <label>Passwort:</label>
              <input type="password" name="password" />
            </div>
            <button type="submit">Anmelden</button>
          </form>
        </body>
      </html>
    `);
  });

  // Fake-Login-Post-Handler
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    logger.info('Login-Versuch', { username, password: '******', ip: clientIP });
    
    // Angriff an API melden - Credential Harvesting
    reportAttack(config, {
      ip_address: clientIP,
      attack_type: 'CREDENTIAL_HARVESTING',
      description: `Login-Versuch mit Benutzername: ${username}`,
      evidence: JSON.stringify({ username, attempt_time: new Date().toISOString() })
    }).catch(error => {
      logger.error('Fehler beim Melden des Login-Versuchs', { error: error.message });
    });

    // Immer mit einer Fehlermeldung antworten
    res.status(401).send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Fehler bei der Anmeldung</title>
        </head>
        <body>
          <h1>Fehler bei der Anmeldung</h1>
          <p>Die eingegebenen Anmeldedaten sind ungültig. Bitte versuchen Sie es erneut.</p>
          <a href="/login">Zurück zum Login</a>
        </body>
      </html>
    `);
  });

  // Fake-Admin-Bereich
  app.get('/admin', (req, res) => {
    res.status(401).send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Admin-Bereich - Zugriff verweigert</title>
        </head>
        <body>
          <h1>Zugriff verweigert</h1>
          <p>Sie müssen angemeldet sein, um auf den Admin-Bereich zugreifen zu können.</p>
          <a href="/login">Zum Login</a>
        </body>
      </html>
    `);
  });

  // Fake-PHP-Info-Seite
  app.get('/phpinfo.php', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>PHP-Info</title>
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

  // Fake-API-Endpunkt
  app.get('/api/users', (req, res) => {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Valid API key required'
    });
  });

  // 404-Handler für alle anderen Anfragen
  app.use((req, res) => {
    res.status(404).send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>404 - Seite nicht gefunden</title>
        </head>
        <body>
          <h1>404 - Seite nicht gefunden</h1>
          <p>Die angeforderte Seite konnte nicht gefunden werden.</p>
        </body>
      </html>
    `);
  });

  logger.info('HTTP-Honeypot-Modul erfolgreich eingerichtet.');
}

// Funktion zur Erkennung von Angriffen
function detectAttack(requestInfo) {
  const { method, path, query, headers, body } = requestInfo;
  
  // Verdächtige Pfade überprüfen
  for (const endpoint of ATTACK_PATTERNS.SUSPICIOUS_ENDPOINTS) {
    if (path.includes(endpoint)) {
      return 'SUSPICIOUS_ENDPOINT';
    }
  }

  // Überprüfe URL-Parameter auf Angriffsmuster
  const queryString = Object.values(query || {}).join(' ');
  
  // SQL-Injection in Query-Parametern
  if (ATTACK_PATTERNS.SQL_INJECTION.some(pattern => queryString.includes(pattern))) {
    return 'SQL_INJECTION';
  }
  
  // Command-Injection in Query-Parametern
  if (ATTACK_PATTERNS.COMMAND_INJECTION.some(pattern => queryString.includes(pattern))) {
    return 'COMMAND_INJECTION';
  }
  
  // XSS in Query-Parametern
  if (ATTACK_PATTERNS.XSS.some(pattern => queryString.includes(pattern))) {
    return 'XSS';
  }
  
  // Path Traversal in Query-Parametern
  if (ATTACK_PATTERNS.PATH_TRAVERSAL.some(pattern => queryString.includes(pattern))) {
    return 'PATH_TRAVERSAL';
  }
  
  // Überprüfe Request-Body, wenn vorhanden
  if (body && typeof body === 'object') {
    const bodyString = JSON.stringify(body);
    
    // SQL-Injection im Body
    if (ATTACK_PATTERNS.SQL_INJECTION.some(pattern => bodyString.includes(pattern))) {
      return 'SQL_INJECTION';
    }
    
    // Command-Injection im Body
    if (ATTACK_PATTERNS.COMMAND_INJECTION.some(pattern => bodyString.includes(pattern))) {
      return 'COMMAND_INJECTION';
    }
    
    // XSS im Body
    if (ATTACK_PATTERNS.XSS.some(pattern => bodyString.includes(pattern))) {
      return 'XSS';
    }
  }
  
  // Überprüfe auf verdächtige User-Agents
  const userAgent = headers['user-agent'] || '';
  if (userAgent.includes('sqlmap') || 
      userAgent.includes('nikto') || 
      userAgent.includes('nmap') || 
      userAgent.includes('wget') || 
      userAgent.includes('curl')) {
    return 'SUSPICIOUS_USER_AGENT';
  }
  
  // Keine bekannten Angriffsmuster erkannt
  return null;
}

module.exports = { setupHTTPHoneypot };