// Custom logger setup - creates different log files for different types of events
const winston = require("winston");
const path = require("path");
const fs = require("fs");

// Make sure we have a logs folder
const logsDir = path.join(process.cwd(), "logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// Custom log levels - added 'suspicious' between info and warn for early detection
const customLevels = {
  levels: {
    error: 0,
    warn: 1,
    suspicious: 2, // New level to catch things before they're full attacks
    info: 3,
    debug: 4,
  },
  colors: {
    error: "red",
    warn: "yellow",
    suspicious: "magenta", // Purple for suspicious activities
    info: "green",
    debug: "blue",
  },
};

// Main logger setup
function setupLogger() {
  // Add our custom colors to winston
  winston.addColors(customLevels.colors);

  // How we format console output - colorized and pretty
  const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp(),
    winston.format.printf(
      (info) =>
        `${info.timestamp} ${info.level}: ${info.message}${
          Object.keys(info).length > 3
            ? " " +
              JSON.stringify(
                Object.fromEntries(
                  Object.entries(info).filter(
                    ([key]) => !["timestamp", "message", "level"].includes(key)
                  )
                ),
                null,
                2
              )
            : ""
        }`
    )
  );

  // How we format file output - JSON for easier parsing
  const fileFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  );

  // Special debug format with more details
  const debugFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp(),
    winston.format.printf((info) => {
      const meta =
        Object.keys(info).length > 3
          ? Object.fromEntries(
              Object.entries(info).filter(
                ([key]) => !["timestamp", "message", "level"].includes(key)
              )
            )
          : null;

      let output = `${info.timestamp} ${info.level}: ${info.message}`;

      if (meta) {
        output += "\n" + JSON.stringify(meta, null, 2);
      }

      return output;
    })
  );

  // Get log level from env vars
  const logLevel =
    process.env.LOG_LEVEL ||
    (process.env.NODE_ENV === "development" ? "debug" : "info");

  // Create the logger with all outputs
  const logger = winston.createLogger({
    levels: customLevels.levels,
    level: logLevel,
    transports: [
      // Console output with format based on environment
      new winston.transports.Console({
        format:
          process.env.NODE_ENV === "development" ? debugFormat : consoleFormat,
      }),
      // General logs
      new winston.transports.File({
        filename: path.join(logsDir, "honeypot.log"),
        format: fileFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5,
      }),
      // Errors only
      new winston.transports.File({
        filename: path.join(logsDir, "error.log"),
        level: "error",
        format: fileFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5,
      }),
      // Attack-specific log
      new winston.transports.File({
        filename: path.join(logsDir, "attacks.log"),
        level: "warn",
        format: fileFormat,
        maxsize: 10485760, // 10MB
        maxFiles: 10,
      }),
      // Suspicious activity log - more sensitive detection
      new winston.transports.File({
        filename: path.join(logsDir, "suspicious.log"),
        level: "suspicious",
        format: fileFormat,
        maxsize: 10485760, // 10MB
        maxFiles: 5,
      }),
      // Debug log only in debug mode
      ...(logLevel === "debug"
        ? [
            new winston.transports.File({
              filename: path.join(logsDir, "debug.log"),
              level: "debug",
              format: fileFormat,
              maxsize: 10485760, // 10MB
              maxFiles: 3,
            }),
          ]
        : []),
    ],
  });

  // Log initial setup
  logger.info(`Logger initialized with level: ${logLevel}`, {
    environment: process.env.NODE_ENV || "production",
    logLevel,
    transports: logger.transports.map((t) => t.name),
  });

  return logger;
}

module.exports = {
  setupLogger,
};
