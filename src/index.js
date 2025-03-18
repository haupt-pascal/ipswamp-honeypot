// Hauptdatei des Honeypot-Services
const express = require('express');
const winston = require('winston');
const { CronJob } = require('cron');
const ip = require('ip');

// Module importieren
const { setupHTTPHoneypot } = require('./modules/http-honeypot');
const { sendHeartbeat, reportAttack } = require('./services/api-service');
const { setupLogger } = require('./utils/logger');

// Konfiguration laden
const config = {
  honeypotId: process.env.HONEYPOT_ID || 'test',
  apiKey: process.env.API_KEY || 'e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a',
  apiEndpoint: process.env.API_ENDPOINT || 'http://localhost:3000/api',
  heartbeatInterval: parseInt(process.env.HEARTBEAT_INTERVAL || '60000'),
  httpPort: parseInt(process.env.HTTP_PORT || '8080'),
  hostIP: process.env.HOST_IP || ip.address()
};

// Logger einrichten
const logger = setupLogger();

// Express-App erstellen
const app = express();

// Middleware für JSON-Parsing
app.use(express.json());

// Heartbeat-Funktion einrichten
async function performHeartbeat() {
  try {
    logger.info('Sende Heartbeat an API-Server...');
    const response = await sendHeartbeat(config);
    logger.info('Heartbeat erfolgreich gesendet', { response });
  } catch (error) {
    logger.error('Fehler beim Senden des Heartbeats', { error: error.message });
  }
}

// Heartbeat beim Start ausführen
performHeartbeat();

// Cron-Job für regelmäßige Heartbeats einrichten (jede Minute)
const heartbeatJob = new CronJob('* * * * *', performHeartbeat);
heartbeatJob.start();

// Haupt-Honeypot-Module einrichten
setupHTTPHoneypot(app, logger, config, reportAttack);

// Füge eine Monitoring-Route hinzu (nicht Teil des Honeypots)
app.get('/monitor', (req, res) => {
  res.status(200).json({
    status: 'running',
    honeypotId: config.honeypotId,
    modules: ['http'],
    uptime: process.uptime()
  });
});

// Server starten
app.listen(config.httpPort, () => {
  logger.info(`Honeypot-Server gestartet auf Port ${config.httpPort}`);
  logger.info(`Konfiguration: ${JSON.stringify(config, null, 2)}`);
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM Signal empfangen. Beende Anwendung...');
  heartbeatJob.stop();
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT Signal empfangen. Beende Anwendung...');
  heartbeatJob.stop();
  process.exit(0);
});