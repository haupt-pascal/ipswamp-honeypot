// Logger-Konfiguration mit Winston
const winston = require("winston");
const path = require("path");
const fs = require("fs");

// Logger-Verzeichnis erstellen, falls es nicht existiert
const logsDir = path.join(process.cwd(), "logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// Logger-Funktion
function setupLogger() {
  // Formatierung für Konsolenausgabe
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

  // Formatierung für Dateiausgabe
  const fileFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  );

  // Debug-Format mit mehr Details für Entwicklung
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

  // Bestimme Log-Level aus Umgebungsvariablen
  const logLevel =
    process.env.LOG_LEVEL ||
    (process.env.NODE_ENV === "development" ? "debug" : "info");

  // Logger erstellen
  const logger = winston.createLogger({
    level: logLevel,
    transports: [
      // Konsolenausgabe mit angepasstem Format je nach Umgebung
      new winston.transports.Console({
        format:
          process.env.NODE_ENV === "development" ? debugFormat : consoleFormat,
      }),
      // Dateiausgabe für allgemeine Logs
      new winston.transports.File({
        filename: path.join(logsDir, "honeypot.log"),
        format: fileFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5,
      }),
      // Separate Datei für Fehler
      new winston.transports.File({
        filename: path.join(logsDir, "error.log"),
        level: "error",
        format: fileFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5,
      }),
      // Separate Datei für Angriffe
      new winston.transports.File({
        filename: path.join(logsDir, "attacks.log"),
        level: "warn",
        format: fileFormat,
        maxsize: 10485760, // 10MB
        maxFiles: 10,
      }),
      // Im Debug-Modus auch detaillierte Debug-Logs speichern
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

  // Log-Level und Konfiguration protokollieren
  logger.info(`Logger initialisiert mit Level: ${logLevel}`, {
    environment: process.env.NODE_ENV || "production",
    logLevel,
    transports: logger.transports.map((t) => t.name),
  });

  return logger;
}

module.exports = {
  setupLogger,
};
