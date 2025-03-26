/**
 * Mail Server Honeypot Module
 *
 * Simulates SMTP, POP3, and IMAP mail servers to detect and analyze attacks
 * targeting mail infrastructure.
 */

const net = require("net");
const fs = require("fs");
const path = require("path");
const { reportAttack } = require("../services/api-service");

// Setup mail honeypot servers (SMTP, POP3, IMAP)
async function setupMailHoneypot(config, logger) {
  const mailServers = [];

  // Ensure mail directory exists
  const mailDir = path.join(process.cwd(), "mail");
  if (!fs.existsSync(mailDir)) {
    fs.mkdirSync(mailDir, { recursive: true });
  }

  // Setup SMTP server
  if (config.smtpPort) {
    const smtpServer = createSMTPServer(config, logger);
    mailServers.push({
      name: "SMTP",
      port: config.smtpPort,
      server: smtpServer,
    });
    logger.info(`SMTP honeypot server started on port ${config.smtpPort}`);
  }

  // Setup SMTP Submission server (usually port 587)
  if (config.smtpSubmissionPort) {
    const smtpSubmissionServer = createSMTPServer(config, logger, true);
    mailServers.push({
      name: "SMTP Submission",
      port: config.smtpSubmissionPort,
      server: smtpSubmissionServer,
    });
    logger.info(
      `SMTP Submission honeypot server started on port ${config.smtpSubmissionPort}`
    );
  }

  // Setup POP3 server
  if (config.pop3Port) {
    const pop3Server = createPOP3Server(config, logger);
    mailServers.push({
      name: "POP3",
      port: config.pop3Port,
      server: pop3Server,
    });
    logger.info(`POP3 honeypot server started on port ${config.pop3Port}`);
  }

  // Setup IMAP server
  if (config.imapPort) {
    const imapServer = createIMAPServer(config, logger);
    mailServers.push({
      name: "IMAP",
      port: config.imapPort,
      server: imapServer,
    });
    logger.info(`IMAP honeypot server started on port ${config.imapPort}`);
  }

  return mailServers;
}

// Create SMTP honeypot server
function createSMTPServer(config, logger, isSubmission = false) {
  const server = net.createServer((socket) => {
    const clientIP = socket.remoteAddress.replace(/^::ffff:/, "");
    const clientPort = socket.remotePort;
    const connectionId = `${clientIP}:${clientPort}`;

    // Session state tracking
    const session = {
      authenticated: false,
      commands: [],
      mailFrom: null,
      rcptTo: [],
      data: [],
      inDataMode: false,
      authAttempts: 0,
      maxAuthAttempts: 3,
      startTime: Date.now(),
    };

    logger.info(`SMTP connection received`, {
      ip: clientIP,
      port: clientPort,
      server: isSubmission ? "submission" : "smtp",
    });

    // SMTP Welcome banner
    socket.write(
      `220 mail.example.com ESMTP ${
        isSubmission ? "Postfix" : "Sendmail 8.15.2"
      } ready\r\n`
    );

    socket.on("data", (data) => {
      const command = data.toString().trim();

      // Add to session command history
      if (command && !session.inDataMode) {
        session.commands.push(command);
      } else if (session.inDataMode) {
        session.data.push(command);
      }

      // Process SMTP commands
      if (session.inDataMode) {
        // In DATA mode, look for end marker
        if (command.endsWith("\r\n.\r\n") || command.endsWith("\n.\n")) {
          session.inDataMode = false;

          // Check for suspicious patterns in email data
          const emailData = session.data.join("\n");
          const isSpam = detectSpam(emailData);

          if (isSpam) {
            reportMailAttack(config, logger, clientIP, "smtp_spam_attempt", {
              commands: session.commands,
              mail_from: session.mailFrom,
              rcpt_to: session.rcptTo,
              data_preview: emailData.substring(0, 500),
            });
          }

          // Always accept the message but do nothing with it
          socket.write("250 Message accepted\r\n");
        }
      } else {
        // Regular command processing
        const commandUpper = command.toUpperCase();

        // Check for SMTP commands
        if (
          commandUpper.startsWith("HELO") ||
          commandUpper.startsWith("EHLO")
        ) {
          // For EHLO, list our "capabilities"
          if (commandUpper.startsWith("EHLO")) {
            const capabilities = [
              "250-mail.example.com",
              "250-PIPELINING",
              "250-SIZE 10240000",
              "250-VRFY",
              "250-ETRN",
              "250-STARTTLS",
              "250-AUTH PLAIN LOGIN",
              "250-ENHANCEDSTATUSCODES",
              "250-8BITMIME",
              "250 DSN",
            ];
            socket.write(capabilities.join("\r\n") + "\r\n");
          } else {
            socket.write("250 mail.example.com\r\n");
          }
        } else if (commandUpper.startsWith("AUTH ")) {
          // Authentication attempt
          session.authAttempts++;

          // Always reject auth after delay
          setTimeout(() => {
            socket.write("535 5.7.8 Authentication credentials invalid\r\n");

            // Report auth attempt
            if (session.authAttempts >= session.maxAuthAttempts) {
              reportMailAttack(config, logger, clientIP, "smtp_auth_attempt", {
                commands: session.commands,
                auth_attempts: session.authAttempts,
              });
            }
          }, 1000);
        } else if (commandUpper.startsWith("MAIL FROM:")) {
          session.mailFrom = command.substring(10).trim();
          socket.write("250 OK\r\n");
        } else if (commandUpper.startsWith("RCPT TO:")) {
          const recipient = command.substring(8).trim();
          session.rcptTo.push(recipient);

          // Check for email harvesting
          if (session.rcptTo.length > 10) {
            reportMailAttack(config, logger, clientIP, "email_harvesting", {
              commands: session.commands,
              rcpt_count: session.rcptTo.length,
            });
          }

          socket.write("250 OK\r\n");
        } else if (commandUpper === "DATA") {
          socket.write("354 Start mail input; end with <CRLF>.<CRLF>\r\n");
          session.inDataMode = true;
        } else if (commandUpper === "RSET") {
          // Reset session
          session.mailFrom = null;
          session.rcptTo = [];
          session.data = [];
          socket.write("250 OK\r\n");
        } else if (commandUpper === "NOOP") {
          socket.write("250 OK\r\n");
        } else if (commandUpper === "QUIT") {
          socket.write(
            "221 mail.example.com Service closing transmission channel\r\n"
          );
          socket.end();
        } else if (
          commandUpper.startsWith("VRFY") ||
          commandUpper.startsWith("EXPN")
        ) {
          socket.write(
            "252 Cannot VRFY user; try RCPT to attempt delivery\r\n"
          );

          // Multiple VRFY commands indicate possible user enumeration
          const vrfyCount = session.commands.filter(
            (cmd) =>
              cmd.toUpperCase().startsWith("VRFY") ||
              cmd.toUpperCase().startsWith("EXPN")
          ).length;

          if (vrfyCount > 5) {
            reportMailAttack(config, logger, clientIP, "email_harvesting", {
              commands: session.commands,
              vrfy_count: vrfyCount,
            });
          }
        } else if (commandUpper === "STARTTLS") {
          socket.write("220 Ready to start TLS\r\n");
          // We don't actually implement TLS, so connection will likely fail after this
        } else {
          // Unknown command
          socket.write("500 Command unrecognized\r\n");
        }
      }
    });

    socket.on("error", (err) => {
      logger.error(`SMTP socket error: ${err.message}`, { clientIP });
    });

    socket.on("close", () => {
      // Session complete, check for suspicious patterns
      const sessionDuration = Date.now() - session.startTime;
      const commandCount = session.commands.length;

      // Report if this looks like a port scan (very short connection)
      if (sessionDuration < 500 && commandCount <= 1) {
        reportMailAttack(config, logger, clientIP, "smtp_scan", {
          duration_ms: sessionDuration,
        });
      }

      // Report relay attempt if many recipients from different domains
      if (session.rcptTo.length > 5) {
        const domains = new Set(
          session.rcptTo.map((rcpt) => {
            const match = rcpt.match(/@([^>]+)/);
            return match ? match[1].toLowerCase() : "";
          })
        );

        if (domains.size > 3) {
          reportMailAttack(config, logger, clientIP, "smtp_relay_attempt", {
            domains: Array.from(domains),
            recipient_count: session.rcptTo.length,
          });
        }
      }

      logger.debug(`SMTP connection closed: ${connectionId}`);
    });
  });

  server.on("error", (err) => {
    logger.error(`SMTP server error: ${err.message}`);
  });

  server.listen(isSubmission ? config.smtpSubmissionPort : config.smtpPort);
  return server;
}

// Create POP3 honeypot server
function createPOP3Server(config, logger) {
  const server = net.createServer((socket) => {
    const clientIP = socket.remoteAddress.replace(/^::ffff:/, "");
    const clientPort = socket.remotePort;
    const connectionId = `${clientIP}:${clientPort}`;

    // Session tracking
    const session = {
      authenticated: false,
      state: "AUTHORIZATION",
      username: null,
      commands: [],
      authAttempts: 0,
      maxAuthAttempts: 3,
      startTime: Date.now(),
    };

    logger.info(`POP3 connection received`, { ip: clientIP, port: clientPort });

    // POP3 Welcome
    socket.write("+OK POP3 server ready <mailserver.example.com>\r\n");

    socket.on("data", (data) => {
      const command = data.toString().trim().toLowerCase();
      session.commands.push(command);

      if (command.startsWith("user ")) {
        session.username = command.substring(5).trim();
        socket.write("+OK\r\n");
      } else if (command.startsWith("pass ")) {
        session.authAttempts++;

        // Always reject after delay
        setTimeout(() => {
          socket.write("-ERR Authentication failed\r\n");

          // Report brute force attempts
          if (session.authAttempts >= session.maxAuthAttempts) {
            reportMailAttack(config, logger, clientIP, "pop3_bruteforce", {
              username: session.username,
              auth_attempts: session.authAttempts,
              commands: session.commands,
            });
          }
        }, 1000);
      } else if (command === "quit") {
        socket.write("+OK Goodbye\r\n");
        socket.end();
      } else if (command === "capa") {
        // POP3 capabilities
        socket.write(
          "+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nEXPIRE NEVER\r\n.\r\n"
        );
      } else if (
        command === "stat" ||
        command === "list" ||
        command === "retr" ||
        command.startsWith("top ") ||
        command === "uidl" ||
        command === "dele"
      ) {
        // These commands require authentication
        if (session.authenticated) {
          if (command === "stat") {
            socket.write("+OK 0 0\r\n"); // No messages
          } else if (command === "list" || command === "uidl") {
            socket.write("+OK\r\n.\r\n"); // Empty list
          } else {
            socket.write("-ERR No such message\r\n");
          }
        } else {
          socket.write("-ERR Command not valid in this state\r\n");
        }
      } else if (command === "noop") {
        socket.write("+OK\r\n");
      } else if (command === "rset") {
        socket.write("+OK\r\n");
      } else {
        socket.write("-ERR Command not recognized\r\n");
      }
    });

    socket.on("error", (err) => {
      logger.error(`POP3 socket error: ${err.message}`, { clientIP });
    });

    socket.on("close", () => {
      // Session complete, check for suspicious patterns
      const sessionDuration = Date.now() - session.startTime;
      const commandCount = session.commands.length;

      // Report likely port scan
      if (sessionDuration < 500 && commandCount <= 1) {
        reportMailAttack(config, logger, clientIP, "pop3_scan", {
          duration_ms: sessionDuration,
        });
      }

      logger.debug(`POP3 connection closed: ${connectionId}`);
    });
  });

  server.on("error", (err) => {
    logger.error(`POP3 server error: ${err.message}`);
  });

  server.listen(config.pop3Port);
  return server;
}

// Create IMAP honeypot server
function createIMAPServer(config, logger) {
  const server = net.createServer((socket) => {
    const clientIP = socket.remoteAddress.replace(/^::ffff:/, "");
    const clientPort = socket.remotePort;
    const connectionId = `${clientIP}:${clientPort}`;

    // Session tracking
    const session = {
      authenticated: false,
      state: "NON_AUTHENTICATED",
      tag: null,
      commands: [],
      authAttempts: 0,
      maxAuthAttempts: 3,
      startTime: Date.now(),
    };

    logger.info(`IMAP connection received`, { ip: clientIP, port: clientPort });

    // IMAP Welcome
    socket.write(
      "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS AUTH=PLAIN AUTH=LOGIN] IMAP server ready\r\n"
    );

    socket.on("data", (data) => {
      const command = data.toString().trim();
      session.commands.push(command);

      // Extract tag and command parts
      const parts = command.split(" ");
      const tag = parts[0];
      const cmd = parts.length > 1 ? parts[1].toUpperCase() : "";

      if (cmd === "LOGIN") {
        session.authAttempts++;

        // Always reject with delay
        setTimeout(() => {
          socket.write(
            `${tag} NO [AUTHENTICATIONFAILED] Authentication failed\r\n`
          );

          // Report brute force attempts
          if (session.authAttempts >= session.maxAuthAttempts) {
            const username = parts.length > 2 ? parts[2] : "unknown";
            reportMailAttack(config, logger, clientIP, "imap_bruteforce", {
              username: username,
              auth_attempts: session.authAttempts,
              commands: session.commands,
            });
          }
        }, 1000);
      } else if (cmd === "CAPABILITY") {
        socket.write(
          "* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS AUTH=PLAIN AUTH=LOGIN\r\n"
        );
        socket.write(`${tag} OK CAPABILITY completed\r\n`);
      } else if (cmd === "LOGOUT") {
        socket.write("* BYE IMAP server terminating connection\r\n");
        socket.write(`${tag} OK LOGOUT completed\r\n`);
        socket.end();
      } else if (cmd === "NOOP") {
        socket.write(`${tag} OK NOOP completed\r\n`);
      } else if (
        [
          "SELECT",
          "EXAMINE",
          "CREATE",
          "DELETE",
          "RENAME",
          "SUBSCRIBE",
          "UNSUBSCRIBE",
          "LIST",
          "LSUB",
          "STATUS",
          "APPEND",
          "CHECK",
          "CLOSE",
          "EXPUNGE",
          "SEARCH",
          "FETCH",
          "STORE",
          "COPY",
          "UID",
        ].includes(cmd)
      ) {
        // These commands require authentication
        if (session.authenticated) {
          socket.write(`${tag} NO Not implemented\r\n`);
        } else {
          socket.write(`${tag} NO Authentication required\r\n`);
        }
      } else if (cmd === "AUTHENTICATE") {
        // Handle various auth methods
        if (parts.length > 2) {
          const authMethod = parts[2].toUpperCase();
          if (authMethod === "PLAIN" || authMethod === "LOGIN") {
            // Some clients send auth data immediately, others need a continuation
            if (parts.length > 3) {
              session.authAttempts++;
              socket.write(`${tag} NO Authentication failed\r\n`);
            } else {
              // Send continuation request
              socket.write("+ \r\n");
            }
          } else {
            socket.write(`${tag} NO Unsupported authentication mechanism\r\n`);
          }
        } else {
          socket.write(`${tag} BAD Missing required argument\r\n`);
        }
      } else if (cmd.startsWith("+")) {
        // Client responding to a continuation request
        session.authAttempts++;
        socket.write(`${tag} NO Authentication failed\r\n`);

        // Report brute force after multiple attempts
        if (session.authAttempts >= session.maxAuthAttempts) {
          reportMailAttack(config, logger, clientIP, "imap_bruteforce", {
            auth_attempts: session.authAttempts,
            commands: session.commands,
          });
        }
      } else {
        socket.write(`${tag} BAD Unknown command\r\n`);
      }
    });

    socket.on("error", (err) => {
      logger.error(`IMAP socket error: ${err.message}`, { clientIP });
    });

    socket.on("close", () => {
      // Session complete, check for suspicious patterns
      const sessionDuration = Date.now() - session.startTime;
      const commandCount = session.commands.length;

      // Report likely port scan
      if (sessionDuration < 500 && commandCount <= 1) {
        reportMailAttack(config, logger, clientIP, "imap_scan", {
          duration_ms: sessionDuration,
        });
      }

      logger.debug(`IMAP connection closed: ${connectionId}`);
    });
  });

  server.on("error", (err) => {
    logger.error(`IMAP server error: ${err.message}`);
  });

  server.listen(config.imapPort);
  return server;
}

// Helper function to detect spam in email content
function detectSpam(emailData) {
  // Simple heuristics to detect spam
  const lowerEmail = emailData.toLowerCase();

  // Check for common spam phrases
  const spamPhrases = [
    "viagra",
    "cialis",
    "pharmacy",
    "discount",
    "free offer",
    "lottery",
    "winner",
    "nigeria",
    "inheritance",
    "million dollars",
    "casino",
    "online gambling",
    "betting",
    "weight loss",
    "diet",
    "enlargement",
    "low rate",
    "cheap",
    "promotion",
    "limited time",
    "buy now",
    "best price",
    "subscribe",
    "unsubscribe",
  ];

  // Check for excessive URLs
  const urlCount = (lowerEmail.match(/https?:\/\//g) || []).length;

  // Check for suspicious content patterns
  const hasHtmlWithHiddenContent =
    lowerEmail.includes('style="display:none"') ||
    lowerEmail.includes("visibility:hidden");

  // Check for common spam indicators
  const hasSpamPhrases = spamPhrases.some((phrase) =>
    lowerEmail.includes(phrase)
  );

  return urlCount > 10 || hasHtmlWithHiddenContent || hasSpamPhrases;
}

// Report mail attack to the API
function reportMailAttack(config, logger, ip, attackType, evidence) {
  const attackData = {
    ip_address: ip,
    attack_type: attackType,
    description: `Mail server ${attackType} detected`,
    evidence: [JSON.stringify(evidence)],
    timestamp: new Date().toISOString(),
  };

  // Report the attack
  reportAttack(config, attackData, logger).catch((error) => {
    logger.error(`Failed to report mail attack: ${error.message}`, {
      ip,
      attack_type: attackType,
    });
  });
}

module.exports = {
  setupMailHoneypot,
};
