// Logger-Konfiguration mit Winston
const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Logger-Verzeichnis erstellen, falls es nicht existiert
const logsDir = path.join(process.cwd(), 'logs');
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
      info => `${info.timestamp} ${info.level}: ${info.message}${
        Object.keys(info).length > 3 ? ' ' + JSON.stringify(
          Object.fromEntries(
            Object.entries(info).filter(([key]) => !['timestamp', 'message', 'level'].includes(key))
          ), 
          null, 2
        ) : ''
      }`
    )
  );

  // Formatierung für Dateiausgabe
  const fileFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  );

  // Logger erstellen
  const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    transports: [
      // Konsolenausgabe
      new winston.transports.Console({
        format: consoleFormat
      }),
      // Dateiausgabe für allgemeine Logs
      new winston.transports.File({
        filename: path.join(logsDir, 'honeypot.log'),
        format: fileFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5
      }),
      // Separate Datei für Fehler
      new winston.transports.File({
        filename: path.join(logsDir, 'error.log'),
        level: 'error',
        format: fileFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5
      }),
      // Separate Datei für Angriffe
      new winston.transports.File({
        filename: path.join(logsDir, 'attacks.log'),
        level: 'warn',
        format: fileFormat,
        maxsize: 10485760, // 10MB
        maxFiles: 10
      })
    ]
  });

  return logger;
}

module.exports = {
  setupLogger
};