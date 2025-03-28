// SSH-Honeypot-Modul
const { Server } = require("ssh2");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// Track connection attempts by IP address
const connectionTracker = new Map();

// Track authentication attempts by IP
const authAttemptTracker = new Map();

// Funktion zum Generieren eines SSH-Schlüsselpaars, falls nicht vorhanden
function generateSSHKeys() {
  const sshDir = path.join(process.cwd(), "keys");
  const privateKeyPath = path.join(sshDir, "ssh_host_rsa_key");
  const publicKeyPath = path.join(sshDir, "ssh_host_rsa_key.pub");

  // Erstelle das Verzeichnis, falls es nicht existiert
  if (!fs.existsSync(sshDir)) {
    fs.mkdirSync(sshDir, { recursive: true });
  }

  // Überprüfe, ob die Schlüssel bereits existieren
  if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
    console.log("Generiere neue SSH-Schlüssel...");

    // Diese Funktion ist nur eine Platzhalter - in der Produktion würde man hier
    // echte Schlüssel mit der crypto-Bibliothek oder über externe Befehle erzeugen
    // Für diesen Honeypot verwenden wir vorgenerierte Schlüssel

    const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1A1jcqpYzP9CwVxvyeBQfPNdS/bZ7+IoO5L4HoL51DFt4cNL
RxWTL3jNKGBWCn9rjezP8FPGlhFenHX2vSAZK0REJI5SSLWk5GPLL/nGwz9UJQp+
lgvZ1QVoTdVv+P+nB+6EUx4nCte9Y9w8yKFP7ECyA+7ZxqYhLvGzKBN8WPdqXKEP
5aKgZs7hlbM3iKJH2GFa4KZ2GZbG2HL9HFyLpR4DGEvBj9j9hf2UzXebF11FeIGV
CqTxVbQtAHvzc6IlVpL9fSo9a6N9WECtCuqMUodDRVKzKDFnRjbVnR78OmlWXtV8
+wquzUJD5Nl0gRZF/QzEXYCBPDYGQdqN1kZ/XQIDAQABAoIBAGCm9j1PvM+7Zlc3
W7ed/QFEKPl4/gLWzp0Zg1p6oE0UXmwzs0isBdsBTxCUu0wRZh5GdG22BQxPvGbL
sbMZyQT7jMPK3tRmHXZo6hHPMqBXDEkqBvbWE5HwKQbX9X67/YBpS5eZTvVV9K6F
KPn82/lYA/hzMxHBea7AVKZA5mJcuonlUj9ZKgVSsnYHzY6aBXnbJBz69+6GwZYi
cjSF9NjwHnCGvRm24B55W70XMBvEqjmCkAQmA3wNZBa5m3IxRX5qMKy82/7r5USH
9Z82mXFoI0Evg4CWtEm+MUZJQPMuK2qGh8OoMHNxQTq2sYBZAKVEgEVcwYu58LiD
8ikU+wECgYEA8DXGMZcMrM7Vp3gFBwnTvzBeXzcxhzUWOeQl/9kiHCXXCjULj5F/
s5dVsvKnfXRXQw3F9K/ADw+9kxGYQQP1bjNg92TU2qJX3VoUqGKwKlfV7sjY8xAM
YEgDtS0lEYUFSg96AH48xXTYPkyMY0E6XUxA3PUdY1Ed1OWZJHwXHh0CgYEA4cEk
c3VGYrmE5Jb/i02xbTsckRkq5C0FlLwRLpN5vGzwcDpqGjNtI+QK4p8QNfm/TVaX
UdPiZ0UeyuJZXNQTVpQbBvCdDUYej3DVQkQkLnZ+DiO/hfR8pWjV+g32MjvzWnrI
w33/bXysMHLeYLNYYJOCaJ2uQD18WK+FjNY401ECgYEAvTBQTtXQwKp8G8Iz8VTm
z8E5y5zwEGqIbXLBwSn52cfpCr1DjdXUwNY3S0hK4MYLYYcU4qpPRQKzAWbGnMLp
zDOlsO9xj6ltYz02dEbhpGUcHDCg2/YVQvh8I2ufXzPOZBy5GvjLg30owt5Ieghw
8MAwBqg8GcAYnH0T5s7p2+0CgYA/PwyuzvL+ZCgQRFHyMSQ3Cj1GgQR1D0F+AC9Y
m1xyJXQXbAUdZXNJ5MYbV1WQpMO9ebT30N4gkKdYYvQh3Rq4YPoZ9fDJlKteLSJx
G1o/5SC40/rys5Vi5iHLEmuI1LJV+tJCEOYxHkznbPJoQVeLmU6IJKoVC9XBEY4F
7PK6sQKBgQDi/qBPNqFu5Fh3MZSHlts49PlWlGpr0PncfQHkPQ0jXHNmwRhK+d2k
1BwHh72BU8YKM8UQQPo6XbvB1E7wvP2XnrUwZHPXJ/wUDOX4SLPYnJL1KZbNW2fV
1x6YdDVxW8o9CVCJ4k7frU9W7uA0QHlNJMNLPfR/zuG3tFiN8MNsiA==
-----END RSA PRIVATE KEY-----`;

    const publicKey =
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUDWNyqljM/0LBXG/J4FB8811L9tnv4ig7kvgegvnUMW3hw0tHFZMveM0oYFYKf2uN7M/wU8aWEV6cdfa9IBkrREQkjlJItaTkY8sv+cbDP1QlCn6WC9nVBWhN1W/4/6cH7oRTHicK171j3DzIoU/sQLID7tnGpiEu8bMoE3xY92pcoQ/loqBmzuGVszeIokfYYVrgpnYZlsbYcv0cXIulHgMYS8GP2P2F/ZTNd5sXXUV4gZUKpPFVtC0Ae/NzoiVWkv19Kj1ro31YQK0K6oxSh0NFUrMoMWdGNtWdHvw6aVZe1Xz7Cq7NQkPk2XSBFkX9DMRdgIE8NgZB2o3WRn9d honeypot@example.com";

    // Schlüssel in Dateien schreiben
    fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });
  }

  return {
    privateKey: fs.readFileSync(privateKeyPath),
    publicKey: fs.readFileSync(publicKeyPath),
  };
}

// Function to track and detect rapid connection attempts
function trackConnectionAttempt(ipAddress, logger, config, reportAttack) {
  // Initialize tracking for this IP if it doesn't exist
  if (!connectionTracker.has(ipAddress)) {
    connectionTracker.set(ipAddress, {
      attempts: [],
      lastReportTime: 0,
    });
  }

  const tracker = connectionTracker.get(ipAddress);
  const now = Date.now();

  // Add this attempt with timestamp
  tracker.attempts.push(now);

  // Remove attempts older than 1 minute
  const oneMinuteAgo = now - 60000;
  tracker.attempts = tracker.attempts.filter((time) => time > oneMinuteAgo);

  // Check if we have enough attempts to report
  // Reduced from 10 to 3 attempts for more sensitive detection
  // and we haven't reported in the last 2 minutes to avoid spam
  if (tracker.attempts.length >= 3 && now - tracker.lastReportTime > 120000) {
    logger.warn(
      `Detected rapid SSH connection attempts from ${ipAddress}: ${tracker.attempts.length} attempts in the last minute`,
      {
        ip: ipAddress,
        attempt_count: tracker.attempts.length,
      }
    );

    // Report as a brute force or scan attempt
    reportAttack(config, {
      ip_address: ipAddress,
      attack_type: "SSH_BRUTEFORCE_SCAN",
      description: `Rapid SSH connection attempts detected: ${tracker.attempts.length} attempts in 1 minute`,
      evidence: JSON.stringify({
        ip_address: ipAddress,
        connection_count: tracker.attempts.length,
        connection_times: tracker.attempts.map((time) =>
          new Date(time).toISOString()
        ),
      }),
    }).catch((error) => {
      logger.error("Failed to report rapid SSH connection attempts", {
        error: error.message,
      });
    });

    // Update last report time
    tracker.lastReportTime = now;
  }
}

// Clean up old connection tracking data periodically
setInterval(() => {
  const now = Date.now();
  const twoHoursAgo = now - 7200000; // 2 hours

  for (const [ip, data] of connectionTracker.entries()) {
    // Remove IPs with no recent activity
    if (
      data.attempts.length === 0 ||
      Math.max(...data.attempts) < twoHoursAgo
    ) {
      connectionTracker.delete(ip);
    }
  }
}, 300000); // Run cleanup every 5 minutes

// Funktion zum Aufsetzen des SSH-Honeypots
function setupSSHHoneypot(logger, config, reportAttack) {
  logger.info("SSH-Honeypot-Modul wird eingerichtet...");

  // SSH-Schlüssel generieren oder laden
  const { privateKey, publicKey } = generateSSHKeys();

  // Liste bekannter Benutzer für den Honeypot (kann erweitert werden)
  const users = {
    root: { password: "password123" },
    admin: { password: "admin123" },
    user: { password: "user123" },
    test: { password: "test123" },
    ubuntu: { password: "ubuntu" },
    pi: { password: "raspberry" },
  };

  // SSH-Server erstellen
  const server = new Server(
    {
      hostKeys: [privateKey],
    },
    (client) => {
      const clientIP = client._sock.remoteAddress;
      const clientPort = client._sock.remotePort;

      logger.info("Neue SSH-Verbindung", {
        ip: clientIP,
        port: clientPort,
      });

      // Track this connection attempt for rapid connection detection
      trackConnectionAttempt(clientIP, logger, config, reportAttack);

      // Verbindungsdaten
      const connectionInfo = {
        ip: clientIP,
        port: clientPort,
        clientId: crypto.randomBytes(8).toString("hex"),
        commands: [],
        connectionTime: new Date().toISOString(),
        hasAuthenticated: false,
      };

      // Report quick connections as potential port scans
      const connectionTimeout = setTimeout(() => {
        if (!connectionInfo.hasAuthenticated) {
          // Report this as a port scan if the connection wasn't an authentication attempt
          reportAttack(config, {
            ip_address: connectionInfo.ip,
            attack_type: "PORT_SCAN",
            description: `SSH port scan detected - connection established without authentication attempt`,
            evidence: JSON.stringify({
              clientId: connectionInfo.clientId,
              connection_time: connectionInfo.connectionTime,
              disconnection_time: new Date().toISOString(),
              ip: connectionInfo.ip,
              port: connectionInfo.port,
            }),
          }).catch((error) => {
            logger.error("Fehler beim Melden des SSH-Port-Scan", {
              error: error.message,
            });
          });
        }
      }, 5000); // Report if no authentication attempt within 5 seconds

      client.on("authentication", (ctx) => {
        // Clear the timeout since we got an auth attempt
        clearTimeout(connectionTimeout);
        connectionInfo.hasAuthenticated = true;

        const authInfo = {
          ip: connectionInfo.ip,
          method: ctx.method,
          username: ctx.username,
          password: ctx.method === "password" ? ctx.password : null,
        };

        logger.info("SSH-Authentifizierungsversuch", authInfo);

        // Track authentication attempts for bruteforce detection
        if (!authAttemptTracker.has(connectionInfo.ip)) {
          authAttemptTracker.set(connectionInfo.ip, {
            attempts: 1,
            lastAttempt: Date.now(),
            usernames: new Set([ctx.username]),
            lastReported: 0,
          });
        } else {
          const tracker = authAttemptTracker.get(connectionInfo.ip);
          tracker.attempts++;
          tracker.lastAttempt = Date.now();
          if (ctx.username) {
            tracker.usernames.add(ctx.username);
          }

          // Report bruteforce attempts after 3 failed logins
          if (
            tracker.attempts >= 3 &&
            Date.now() - tracker.lastReported > 60000
          ) {
            logger.warn(
              `Possible SSH login bruteforce from ${connectionInfo.ip}: ${tracker.attempts} attempts`,
              {
                ip: connectionInfo.ip,
                attempts: tracker.attempts,
                usernames: Array.from(tracker.usernames),
              }
            );

            // Report the bruteforce attempt with more detailed information
            reportAttack(config, {
              ip_address: connectionInfo.ip,
              attack_type: "SSH_BRUTEFORCE",
              description: `SSH bruteforce detected: ${tracker.attempts} attempts with ${tracker.usernames.size} unique usernames`,
              evidence: JSON.stringify({
                ip: connectionInfo.ip,
                attempts: tracker.attempts,
                usernames: Array.from(tracker.usernames),
                client_id: connectionInfo.clientId,
                timestamp: new Date().toISOString(),
              }),
            }).catch((error) => {
              logger.error("Failed to report SSH bruteforce", {
                error: error.message,
              });
            });

            // Update last reported time
            tracker.lastReported = Date.now();
          }
        }

        // Melde den Anmeldungsversuch an die API
        reportAttack(config, {
          ip_address: connectionInfo.ip,
          attack_type: "SSH_BRUTEFORCE",
          description: `SSH-Anmeldungsversuch: Benutzer: ${ctx.username}, Methode: ${ctx.method}`,
          evidence: JSON.stringify(authInfo),
        }).catch((error) => {
          logger.error("Fehler beim Melden des SSH-Anmeldungsversuchs", {
            error: error.message,
          });
        });

        // Prüfe, ob der Benutzer existiert und das Passwort korrekt ist
        if (
          ctx.method === "password" &&
          users[ctx.username] &&
          users[ctx.username].password === ctx.password
        ) {
          // Authentifizierung erfolgreich - in einem echten Honeypot würden wir hier
          // eventuell die Anmeldung zulassen, um das Verhalten zu beobachten
          ctx.accept();
        } else {
          // Authentifizierung fehlgeschlagen
          // Bei einem echten Honeypot könnte man nach einer bestimmten Anzahl von Versuchen
          // die Authentifizierung akzeptieren, um das Verhalten zu beobachten
          ctx.reject();
        }
      });

      client.on("ready", () => {
        logger.info("SSH-Client authentifiziert", {
          clientId: connectionInfo.clientId,
          ip: connectionInfo.ip,
        });

        client.on("session", (accept, reject) => {
          const session = accept();

          session.on("exec", (accept, reject, info) => {
            logger.info("SSH-Kommando ausgeführt", {
              clientId: connectionInfo.clientId,
              command: info.command,
            });

            // Kommando zur Liste hinzufügen
            connectionInfo.commands.push(info.command);

            // Melde das Kommando an die API
            reportAttack(config, {
              ip_address: connectionInfo.ip,
              attack_type: "SSH_COMMAND",
              description: `SSH-Kommando ausgeführt: ${info.command}`,
              evidence: JSON.stringify({
                clientId: connectionInfo.clientId,
                command: info.command,
                timestamp: new Date().toISOString(),
              }),
            }).catch((error) => {
              logger.error("Fehler beim Melden des SSH-Kommandos", {
                error: error.message,
              });
            });

            // Kanal für die Antwort erzeugen
            const channel = accept();

            // Simulierte Ausgabe generieren
            let output = `Command '${info.command}' executed.\r\n`;

            // Befehle simulieren
            if (info.command.includes("ls")) {
              output =
                "total 20\r\ndrwxr-xr-x 2 root root 4096 Mar 18 12:34 .\r\ndrwxr-xr-x 4 root root 4096 Mar 18 12:30 ..\r\n-rw-r--r-- 1 root root  220 Mar 18 12:28 .bash_logout\r\n-rw-r--r-- 1 root root 3771 Mar 18 12:28 .bashrc\r\n-rw-r--r-- 1 root root  807 Mar 18 12:28 .profile\r\n";
            } else if (info.command.includes("cat /etc/passwd")) {
              output =
                "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\r\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\r\nsync:x:4:65534:sync:/bin:/bin/sync\r\n";
            } else if (info.command.includes("uname")) {
              output =
                "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP Tue Apr 2 14:00:20 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\r\n";
            } else if (info.command.includes("whoami")) {
              output = "root\r\n";
            } else if (info.command.includes("id")) {
              output = "uid=0(root) gid=0(root) groups=0(root)\r\n";
            } else if (info.command.includes("ps")) {
              output =
                "  PID TTY          TIME CMD\r\n    1 ?        00:00:01 systemd\r\n    2 ?        00:00:00 kthreadd\r\n   11 ?        00:00:00 rcu_sched\r\n   12 ?        00:00:00 rcu_bh\r\n  998 ?        00:00:00 sshd\r\n 1000 ?        00:00:00 bash\r\n 1045 ?        00:00:00 ps\r\n";
            }

            channel.write(output);
            channel.exit(0);
            channel.end();
          });

          session.on("shell", (accept, reject) => {
            logger.info("SSH-Shell gestartet", {
              clientId: connectionInfo.clientId,
            });

            const channel = accept();

            // Shell-Banner anzeigen
            channel.write(
              "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
            );
            channel.write(" * Documentation:  https://help.ubuntu.com\r\n");
            channel.write(
              " * Management:     https://landscape.canonical.com\r\n"
            );
            channel.write(
              " * Support:        https://ubuntu.com/advantage\r\n\r\n"
            );

            channel.write(
              "This system has been minimized by removing packages and content that are\r\n"
            );
            channel.write(
              "not required on a system that users do not log into.\r\n\r\n"
            );

            channel.write("root@honeypot:~# ");

            let buffer = "";

            channel.on("data", (data) => {
              const input = data.toString();

              // Echo eingabe
              channel.write(input);

              // Behandle Enter-Taste (Carriage Return)
              if (input === "\r") {
                channel.write("\n");

                if (buffer.length > 0) {
                  logger.info("SSH-Shell-Kommando", {
                    clientId: connectionInfo.clientId,
                    command: buffer,
                  });

                  // Kommando zur Liste hinzufügen
                  connectionInfo.commands.push(buffer);

                  // Melde das Kommando an die API
                  reportAttack(config, {
                    ip_address: connectionInfo.ip,
                    attack_type: "SSH_SHELL_COMMAND",
                    description: `SSH-Shell-Kommando: ${buffer}`,
                    evidence: JSON.stringify({
                      clientId: connectionInfo.clientId,
                      command: buffer,
                      timestamp: new Date().toISOString(),
                    }),
                  }).catch((error) => {
                    logger.error("Fehler beim Melden des SSH-Shell-Kommandos", {
                      error: error.message,
                    });
                  });

                  // Simulierte Ausgabe generieren
                  let output = "";

                  if (buffer === "ls") {
                    output =
                      "total 20\r\ndrwxr-xr-x 2 root root 4096 Mar 18 12:34 .\r\ndrwxr-xr-x 4 root root 4096 Mar 18 12:30 ..\r\n-rw-r--r-- 1 root root  220 Mar 18 12:28 .bash_logout\r\n-rw-r--r-- 1 root root 3771 Mar 18 12:28 .bashrc\r\n-rw-r--r-- 1 root root  807 Mar 18 12:28 .profile\r\n";
                  } else if (buffer === "cat /etc/passwd") {
                    output =
                      "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\r\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\r\nsync:x:4:65534:sync:/bin:/bin/sync\r\n";
                  } else if (buffer === "uname -a") {
                    output =
                      "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP Tue Apr 2 14:00:20 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\r\n";
                  } else if (buffer === "whoami") {
                    output = "root\r\n";
                  } else if (buffer === "id") {
                    output = "uid=0(root) gid=0(root) groups=0(root)\r\n";
                  } else if (buffer === "ps aux") {
                    output =
                      "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\nroot         1  0.0  0.1 169624 11252 ?        Ss   12:28   0:01 /sbin/init\r\nroot         2  0.0  0.0      0     0 ?        S    12:28   0:00 [kthreadd]\r\nroot         3  0.0  0.0      0     0 ?        I<   12:28   0:00 [rcu_gp]\r\nroot       998  0.0  0.1  13488  7456 ?        Ss   12:30   0:00 /usr/sbin/sshd -D\r\nroot      1000  0.0  0.1  10124  5512 ?        Ss   12:34   0:00 bash\r\nroot      1045  0.0  0.1  12108  3512 ?        R+   12:35   0:00 ps aux\r\n";
                  } else if (buffer === "exit") {
                    channel.write("logout\r\n");
                    channel.close();
                    return;
                  } else if (buffer.length > 0) {
                    output = `bash: ${buffer}: command not found\r\n`;
                  }

                  if (output) {
                    channel.write(output);
                  }

                  // Eingabeaufforderung zurücksetzen
                  channel.write("root@honeypot:~# ");

                  // Buffer zurücksetzen
                  buffer = "";
                } else {
                  // Leerer Befehl (nur Enter)
                  channel.write("root@honeypot:~# ");
                }
              }
              // Behandle Backspace
              else if (input === "\x7f" || input === "\b") {
                if (buffer.length > 0) {
                  buffer = buffer.slice(0, -1);
                  // Backspace, space, backspace um das Zeichen zu löschen
                  channel.write("\b \b");
                }
              }
              // Normale Zeichen
              else {
                buffer += input;
              }
            });
          });

          session.on("pty", (accept, reject, info) => {
            logger.info("SSH-PTY angefordert", {
              clientId: connectionInfo.clientId,
              term: info.term,
              width: info.cols,
              height: info.rows,
            });
            accept();
          });
        });
      });

      client.on("end", () => {
        // Clear the timeout when connection ends naturally
        clearTimeout(connectionTimeout);

        logger.info("SSH-Verbindung beendet", {
          clientId: connectionInfo.clientId,
          commandCount: connectionInfo.commands.length,
        });
      });

      client.on("error", (err) => {
        // Clear the timeout on error
        clearTimeout(connectionTimeout);

        logger.error("SSH-Verbindungsfehler", {
          clientId: connectionInfo.clientId,
          error: err.message,
        });
      });
    }
  );

  // Clean up auth tracker periodically to prevent memory leaks
  setInterval(() => {
    const now = Date.now();
    // Clean up trackers older than 1 hour
    for (const [ip, data] of authAttemptTracker.entries()) {
      if (now - data.lastAttempt > 3600000) {
        authAttemptTracker.delete(ip);
      }
    }
  }, 300000); // Run every 5 minutes

  // Server auf TCP-Port 2222 starten (nicht 22, um Konflikte zu vermeiden)
  const sshPort = parseInt(process.env.SSH_PORT || "2222");
  server.listen(sshPort, "0.0.0.0", () => {
    logger.info(`SSH-Honeypot gestartet auf Port ${sshPort}`);
  });

  return server;
}

module.exports = { setupSSHHoneypot };
