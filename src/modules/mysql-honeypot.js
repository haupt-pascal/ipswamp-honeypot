/**
 * MySQL Honeypot
 *
 * Fake MySQL server that catches hackers trying to break into databases
 */

const net = require("net");
const fs = require("fs");
const path = require("path");
const { reportAttack } = require("../services/api-service");

// What MySQL version we pretend to be
const MYSQL_SERVER_VERSION = "5.7.38-log";

// MySQL protocol stuff
const MYSQL_PROTOCOL = {
  OK_PACKET: 0x00,
  EOF_PACKET: 0xfe,
  ERROR_PACKET: 0xff,
  HANDSHAKE: 0x0a,
};

// Set up the MySQL honeypot
async function setupMySQLHoneypot(config, logger) {
  // Make sure we have a MySQL folder
  const mysqlDir = path.join(process.cwd(), "mysql");
  if (!fs.existsSync(mysqlDir)) {
    fs.mkdirSync(mysqlDir, { recursive: true });
  }

  // Create and start the fake MySQL server
  const server = net.createServer((socket) => {
    const clientIP = socket.remoteAddress.replace(/^::ffff:/, "");
    const clientPort = socket.remotePort;
    const connectionId = `${clientIP}:${clientPort}`;

    // Keep track of the session
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

    // Send welcome packet
    sendHandshakePacket(socket, session);

    socket.on("data", (data) => {
      session.lastActivity = Date.now();

      try {
        if (session.state === "HANDSHAKE_SENT") {
          // Client trying to log in
          session.authAttempts++;

          // Grab username but always reject auth
          const username = parseUsernameFromAuthPacket(data);
          session.username = username || "unknown";

          // Fake a delay like we're checking
          setTimeout(() => {
            // Always say login failed
            sendErrorPacket(
              socket,
              1045,
              "Access denied for user '" +
                session.username +
                "'@'" +
                clientIP +
                "' (using password: YES)"
            );

            // Report if they keep trying
            if (session.authAttempts >= session.maxAuthAttempts) {
              reportMySQLAttack(config, logger, clientIP, "mysql_bruteforce", {
                username: session.username,
                auth_attempts: session.authAttempts,
              });
            }
          }, 500);
        } else if (session.state === "AUTHENTICATED") {
          // This shouldn't happen since we never auth anyone
          const query = parseQueryFromPacket(data);
          session.queries.push(query);

          // Look for SQL injection
          if (detectSQLi(query)) {
            reportMySQLAttack(config, logger, clientIP, "mysql_sqli_attempt", {
              query: query,
              username: session.username,
            });
          }

          // Always say there's an error
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

      // Check for suspicious patterns
      const sessionDuration = Date.now() - session.startTime;

      // Super quick connection + disconnect = likely a port scan
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

// Send MySQL handshake packet
function sendHandshakePacket(socket, session) {
  // This is a simplified version - real MySQL has more complex protocol
  // We just need enough to trick scanners/hackers

  // Make a random salt
  const salt = Buffer.from(
    Array(20)
      .fill(0)
      .map(() => Math.floor(Math.random() * 256))
  );

  // Build the packet with version and connection ID etc
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

  // Make final packet with header
  const size = offset;
  const header = Buffer.alloc(4);
  header.writeUInt32LE((size << 8) + 0, 0); // Size in 3 bytes + 1 byte for sequence id

  // Send it
  socket.write(
    Buffer.concat([header.slice(0, 3), Buffer.from([0]), packet.slice(0, size)])
  );
}

// Send MySQL error packet
function sendErrorPacket(socket, errorCode, message) {
  // Build error packet
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

  // Make final packet with header
  const size = offset;
  const header = Buffer.alloc(4);
  header.writeUInt32LE((size << 8) + 1, 0); // Size in 3 bytes + 1 byte for sequence id

  // Send packet
  socket.write(
    Buffer.concat([header.slice(0, 3), Buffer.from([1]), packet.slice(0, size)])
  );
}

// Pull username from auth packet (simplified)
function parseUsernameFromAuthPacket(data) {
  try {
    // Super simplified parsing - real MySQL protocol is more complex
    const offset = 36; // Username usually starts around offset 36
    const usernameBytes = [];

    for (let i = offset; i < data.length; i++) {
      if (data[i] === 0) break; // Username is null-terminated
      usernameBytes.push(data[i]);
    }

    return Buffer.from(usernameBytes).toString("utf8");
  } catch (err) {
    return "unknown"; // If we can't parse, just return unknown
  }
}

// Pull SQL query from packet (simplified)
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

// Look for SQL injection in queries
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

  // See if any pattern matches
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

  // Send the report
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
