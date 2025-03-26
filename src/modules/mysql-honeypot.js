/**
 * MySQL Honeypot Module
 *
 * Simulates a MySQL server to detect and analyze database attacks.
 */

const net = require("net");
const fs = require("fs");
const path = require("path");
const { reportAttack } = require("../services/api-service");

// MySQL server version to emulate
const MYSQL_SERVER_VERSION = "5.7.38-log";

// MySQL protocol constants
const MYSQL_PROTOCOL = {
  OK_PACKET: 0x00,
  EOF_PACKET: 0xfe,
  ERROR_PACKET: 0xff,
  HANDSHAKE: 0x0a,
};

// Setup MySQL honeypot server
async function setupMySQLHoneypot(config, logger) {
  // Ensure MySQL directory exists
  const mysqlDir = path.join(process.cwd(), "mysql");
  if (!fs.existsSync(mysqlDir)) {
    fs.mkdirSync(mysqlDir, { recursive: true });
  }

  // Create and start the MySQL server
  const server = net.createServer((socket) => {
    const clientIP = socket.remoteAddress.replace(/^::ffff:/, "");
    const clientPort = socket.remotePort;
    const connectionId = `${clientIP}:${clientPort}`;

    // Session tracking
    const session = {
      state: "HANDSHAKE_SENT",
      connected: true,
      connectionId: Math.floor(Math.random() * 1000000),
      authAttempts: 0,
      maxAuthAttempts: 3,
      queries: [],
      startTime: Date.now(),
      lastActivity: Date.now(),
    };

    logger.info(`MySQL connection received`, {
      ip: clientIP,
      port: clientPort,
    });

    // Send initial handshake packet
    sendHandshakePacket(socket, session);

    socket.on("data", (data) => {
      session.lastActivity = Date.now();

      try {
        if (session.state === "HANDSHAKE_SENT") {
          // Client is sending authentication response
          session.authAttempts++;

          // Parse auth details, but always reject auth
          const username = parseUsernameFromAuthPacket(data);
          session.username = username || "unknown";

          // Delay response to simulate checking
          setTimeout(() => {
            // Send error packet as if authentication failed
            sendErrorPacket(
              socket,
              1045,
              "Access denied for user '" +
                session.username +
                "'@'" +
                clientIP +
                "' (using password: YES)"
            );

            // Report brute force attempts
            if (session.authAttempts >= session.maxAuthAttempts) {
              reportMySQLAttack(config, logger, clientIP, "mysql_bruteforce", {
                username: session.username,
                auth_attempts: session.authAttempts,
              });
            }
          }, 500);
        } else if (session.state === "AUTHENTICATED") {
          // This should never happen since we don't authenticate anyone
          const query = parseQueryFromPacket(data);
          session.queries.push(query);

          // Store suspicious queries
          if (detectSQLi(query)) {
            reportMySQLAttack(config, logger, clientIP, "mysql_sqli_attempt", {
              query: query,
              username: session.username,
            });
          }

          // Always respond with an error
          sendErrorPacket(socket, 1064, "You have an error in your SQL syntax");
        }
      } catch (err) {
        logger.error(`Failed to process MySQL packet: ${err.message}`, {
          clientIP,
        });
        sendErrorPacket(
          socket,
          1053,
          "Server error occurred while processing request"
        );
      }
    });

    socket.on("error", (err) => {
      logger.error(`MySQL socket error: ${err.message}`, { clientIP });
      session.connected = false;
    });

    socket.on("close", () => {
      session.connected = false;

      // Session complete, check for suspicious patterns
      const sessionDuration = Date.now() - session.startTime;

      // Report likely port scan
      if (sessionDuration < 500 && session.authAttempts === 0) {
        reportMySQLAttack(config, logger, clientIP, "mysql_scan", {
          duration_ms: sessionDuration,
        });
      }

      logger.debug(`MySQL connection closed: ${connectionId}`);
    });
  });

  server.on("error", (err) => {
    logger.error(`MySQL server error: ${err.message}`);
  });

  server.listen(config.mysqlPort);
  logger.info(`MySQL honeypot server started on port ${config.mysqlPort}`);

  return [
    {
      name: "MySQL",
      port: config.mysqlPort,
      server: server,
    },
  ];
}

// Send initial handshake packet
function sendHandshakePacket(socket, session) {
  // This is a simplified version of the MySQL handshake packet
  // In a real implementation, more protocol details would need to be implemented

  // Construct handshake packet with random salt
  const salt = Buffer.from(
    Array(20)
      .fill(0)
      .map(() => Math.floor(Math.random() * 256))
  );

  // Protocol version (10) + server version + connection ID + salt, etc.
  const packet = Buffer.alloc(128);
  let offset = 0;

  // Packet header (length + sequence)
  packet.writeUInt8(MYSQL_PROTOCOL.HANDSHAKE, offset++); // Protocol version
  offset += packet.write(MYSQL_SERVER_VERSION + "\0", offset); // Server version null-terminated

  // Connection ID
  packet.writeUInt32LE(session.connectionId, offset);
  offset += 4;

  // Auth plugin data part 1 (8 bytes of salt)
  salt.copy(packet, offset, 0, 8);
  offset += 8;

  packet.writeUInt8(0, offset++); // Filler

  // Capability flags (lower 2 bytes)
  packet.writeUInt16LE(0xffff, offset);
  offset += 2;

  // Character set
  packet.writeUInt8(0x21, offset++); // utf8_general_ci

  // Status flags
  packet.writeUInt16LE(0x0002, offset); // Server status
  offset += 2;

  // Capability flags (upper 2 bytes)
  packet.writeUInt16LE(0xffff, offset);
  offset += 2;

  // Length of auth plugin data
  packet.writeUInt8(21, offset++);

  // Reserved (10 bytes of 0)
  offset += 10;

  // Auth plugin data part 2
  salt.copy(packet, offset, 8, 20);
  offset += 12;

  // Auth plugin name
  offset += packet.write("mysql_native_password\0", offset);

  // Construct final packet with header
  const size = offset;
  const header = Buffer.alloc(4);
  header.writeUInt32LE((size << 8) + 0, 0); // Size in 3 bytes + 1 byte for sequence id

  // Send packet
  socket.write(
    Buffer.concat([header.slice(0, 3), Buffer.from([0]), packet.slice(0, size)])
  );
}

// Send MySQL error packet
function sendErrorPacket(socket, errorCode, message) {
  // Construct error packet
  const packet = Buffer.alloc(512);
  let offset = 0;

  // Error packet marker
  packet.writeUInt8(MYSQL_PROTOCOL.ERROR_PACKET, offset++);

  // Error code
  packet.writeUInt16LE(errorCode, offset);
  offset += 2;

  // SQL state marker (#)
  packet.writeUInt8(0x23, offset++);

  // SQL state (5 characters)
  offset += packet.write("28000", offset);

  // Error message
  offset += packet.write(message, offset);

  // Construct final packet with header
  const size = offset;
  const header = Buffer.alloc(4);
  header.writeUInt32LE((size << 8) + 1, 0); // Size in 3 bytes + 1 byte for sequence id

  // Send packet
  socket.write(
    Buffer.concat([header.slice(0, 3), Buffer.from([1]), packet.slice(0, size)])
  );
}

// Extract username from authentication packet (simplified)
function parseUsernameFromAuthPacket(data) {
  try {
    // Very simplified parsing - in real implementation would need more detailed protocol handling
    const offset = 36; // Usually username starts around offset 36
    const usernameBytes = [];

    for (let i = offset; i < data.length; i++) {
      if (data[i] === 0) break; // Username is null-terminated
      usernameBytes.push(data[i]);
    }

    return Buffer.from(usernameBytes).toString("utf8");
  } catch (err) {
    return "unknown"; // If parsing fails, return unknown
  }
}

// Extract SQL query from COM_QUERY packet (simplified)
function parseQueryFromPacket(data) {
  try {
    // First byte of payload is command type, 3 for COM_QUERY
    // Query text starts at offset 5 (after packet header and command byte)
    const queryText = data.slice(5).toString("utf8");
    return queryText;
  } catch (err) {
    return ""; // If parsing fails, return empty string
  }
}

// Detect SQL injection attempts in queries
function detectSQLi(query) {
  if (!query) return false;

  const lowerQuery = query.toLowerCase();

  // Common SQL injection patterns
  const patterns = [
    "union select",
    "or 1=1",
    "or 1 =1",
    "or '1'='1",
    'or "1"="1',
    "having 1=1",
    "group by",
    "information_schema",
    "into outfile",
    "load_file",
    "sleep(",
    "benchmark(",
    "hex(",
    "drop table",
    "drop database",
    "delete from",
    "insert into",
    "waitfor delay",
  ];

  // Check if query contains SQL injection patterns
  return patterns.some((pattern) => lowerQuery.includes(pattern));
}

// Report MySQL attack to the API
function reportMySQLAttack(config, logger, ip, attackType, evidence) {
  const attackData = {
    ip_address: ip,
    attack_type: attackType,
    description: `MySQL server ${attackType} detected`,
    evidence: [JSON.stringify(evidence)],
    timestamp: new Date().toISOString(),
  };

  // Report the attack
  reportAttack(config, attackData, logger).catch((error) => {
    logger.error(`Failed to report MySQL attack: ${error.message}`, {
      ip,
      attack_type: attackType,
    });
  });
}

module.exports = {
  setupMySQLHoneypot,
};
