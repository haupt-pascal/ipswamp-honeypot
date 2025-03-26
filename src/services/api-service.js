// API-Service für die Kommunikation mit dem Backend
const axios = require("axios");

// Import the attack pattern adapter
const { enhanceAttackData } = require("../utils/attack-pattern-adapter");

// Speichere die letzte Heartbeat-Anfrage und -Antwort für Debugging
let lastHeartbeatRequest = null;
let lastHeartbeatResponse = null;
let lastHeartbeatError = null;

// Cache für gemeldete IP-Adressen
// Format: { ip_address: { timestamp: Date, attack_types: Set, reported_count: number } }
const reportedIPCache = new Map();

// Konfiguration für das IP-Reporting-Throttling
const IP_CACHE_TTL = 3600000; // 1 Stunde in Millisekunden
const MAX_REPORTS_PER_IP_PER_HOUR = 5; // Maximal 5 Berichte pro IP pro Stunde
const REPORT_TYPES_THROTTLE = true; // Nur neue Angriffstypen für bereits gemeldete IPs berichten

// Heartbeat-Funktion zum Registrieren des Honeypots bei der API
async function sendHeartbeat(config, logger) {
  // Optionaler logger-Parameter für mehr Details
  const log = logger || console;

  // Erstelle Anfrage-Objekt für Debugging
  const requestData = {
    honeypot_id: config.honeypotId,
  };

  const requestConfig = {
    url: `${config.apiEndpoint}/honeypot/heartbeat`,
    method: "POST",
    params: {
      api_key: config.apiKey,
    },
    data: requestData,
    headers: {
      "Content-Type": "application/json",
      "User-Agent": `IPSwamp-Honeypot/${require("../../package.json").version}`,
    },
  };

  lastHeartbeatRequest = {
    timestamp: new Date().toISOString(),
    url: requestConfig.url,
    method: requestConfig.method,
    params: { ...requestConfig.params, api_key: "***redacted***" }, // Verberge API-Key für Logs
    data: requestConfig.data,
    headers: requestConfig.headers,
  };

  try {
    // Debug-Logging vor der Anfrage
    if (config.debugMode) {
      log.debug("Sende Heartbeat-Anfrage", {
        endpoint: requestConfig.url,
        honeypot_id: requestData.honeypot_id,
        headers: requestConfig.headers,
      });
    }

    // Create a custom axios instance for this request with specific config
    const instance = axios.create({
      timeout: 10000,
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      decompress: true,
      maxRedirects: 5,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    });

    // Use the instance for the request
    const response = await instance({
      url: requestConfig.url,
      method: requestConfig.method,
      params: requestConfig.params,
      data: requestConfig.data,
      headers: requestConfig.headers,
    });

    // Speichere Antwort für Debugging
    lastHeartbeatResponse = {
      timestamp: new Date().toISOString(),
      status: response.status,
      statusText: response.statusText,
      data: response.data,
      headers: response.headers,
    };

    lastHeartbeatError = null;

    // Debug-Logging nach erfolgreicher Anfrage
    if (config.debugMode) {
      log.debug("Heartbeat-Antwort erhalten", {
        status: response.status,
        data: response.data,
      });
    }

    return response.data;
  } catch (error) {
    // Detaillierte Fehlerinformationen erfassen
    lastHeartbeatError = {
      timestamp: new Date().toISOString(),
      message: error.message,
      code: error.code,
      response: error.response
        ? {
            status: error.response.status,
            statusText: error.response.statusText,
            data: error.response.data,
            headers: error.response.headers,
          }
        : null,
    };

    // Ausführlicheres Logging basierend auf Fehlertyp
    if (error.response) {
      // Der Server hat geantwortet, aber mit einem Fehlercode
      log.error(
        `Heartbeat-Fehler: Server antwortete mit Status ${error.response.status}`,
        {
          status: error.response.status,
          statusText: error.response.statusText,
          data: error.response.data,
        }
      );
    } else if (error.request) {
      // Die Anfrage wurde gestellt, aber keine Antwort erhalten
      log.error("Heartbeat-Fehler: Keine Antwort vom Server erhalten", {
        message: error.message,
        code: error.code,
      });
    } else {
      // Ein Fehler beim Konfigurieren der Anfrage
      log.error("Heartbeat-Fehler: Konfigurationsfehler", {
        message: error.message,
      });
    }

    throw error;
  }
}

// Funktion zum Melden von erkannten Angriffen
async function reportAttack(config, attackData, logger) {
  const log = logger || console;

  // Enhance attack data with standardized types and severity
  const enhancedData = enhanceAttackData(attackData);

  // Extrahiere IP und Angriffstyp
  const { ip_address, attack_type } = enhancedData;

  // Überprüfe, ob diese IP mit diesem Angriffstyp kürzlich gemeldet wurde
  if (shouldThrottleReport(ip_address, attack_type)) {
    if (config.debugMode) {
      log.debug(
        `IP ${ip_address} wurde kürzlich mit Angriffstyp ${attack_type} gemeldet - Bericht gedrosselt`,
        {
          ip: ip_address,
          attack_type: attack_type,
          original_type: attackData.attack_type,
          cache_info: reportedIPCache.get(ip_address),
        }
      );
    }

    // Inkrementiere Zähler, auch wenn nicht gemeldet wird
    updateReportCache(ip_address, attack_type);

    // Speichere trotzdem lokal, falls gewünscht
    if (config.storeThrottledAttacks) {
      storeAttackLocally({
        ...enhancedData,
        throttled: true,
      });
    }

    return {
      status: "throttled",
      timestamp: new Date().toISOString(),
      message: `IP was recently reported with attack type ${attack_type}, throttling to avoid duplicate reports`,
    };
  }

  // Aktualisiere den Cache mit dieser Meldung
  updateReportCache(ip_address, attack_type);

  // Check if we're in offline mode
  if (config.offlineMode) {
    log.info("Offline-Modus: Angriff lokal gespeichert", {
      attack_type: enhancedData.attack_type,
      ip_address: enhancedData.ip_address,
    });
    storeAttackLocally(enhancedData);
    return { status: "stored_locally", timestamp: new Date().toISOString() };
  }

  try {
    if (config.debugMode) {
      log.debug("Melde Angriff an API", {
        endpoint: `${config.apiEndpoint}/honeypot/report-ip`,
        type: enhancedData.attack_type,
      });
    }

    // Format evidence as array if it's a string
    let evidence = enhancedData.evidence;
    if (typeof evidence === "string") {
      try {
        // Try to parse JSON string
        const parsedEvidence = JSON.parse(evidence);
        evidence = Array.isArray(parsedEvidence) ? parsedEvidence : [evidence];
      } catch (e) {
        // If not valid JSON, use as a single element array
        evidence = [evidence];
      }
    } else if (evidence && !Array.isArray(evidence)) {
      // Convert non-array objects to array
      evidence = [JSON.stringify(evidence)];
    }

    // Prepare the request body according to the API specification
    const requestBody = {
      ip_address: enhancedData.ip_address,
      attack_type: enhancedData.attack_type,
      description: enhancedData.description,
      evidence: evidence,
      severity: enhancedData.severity,
      category: enhancedData.category,
      source: "honeypot",
    };

    // Create a custom axios instance for this request with specific config
    const instance = axios.create({
      timeout: 5000,
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      decompress: true,
      maxRedirects: 5,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    });

    // Use the instance for the request
    const response = await instance.post(
      `${config.apiEndpoint}/honeypot/report-ip`,
      requestBody,
      {
        params: {
          api_key: config.apiKey,
        },
      }
    );

    log.debug("Angriff erfolgreich gemeldet", {
      status: response.status,
      attack_type: enhancedData.attack_type,
      score: response.data?.current_score,
      ip_id: response.data?.ip_id,
    });

    return response.data;
  } catch (error) {
    // More detailed error logging
    const errorDetails = {
      error: error.message,
      attackType: enhancedData.attack_type,
      statusCode: error.response?.status,
      statusText: error.response?.statusText,
      data: error.response?.data,
      apiEndpoint: `${config.apiEndpoint}/honeypot/report-ip`,
    };

    log.error("Fehler beim Melden des Angriffs", errorDetails);

    // If we get 403 forbidden, it could be an API key issue
    if (error.response && error.response.status === 403) {
      log.warn("API-Key hat keine Berechtigung für Angriffsmeldungen", {
        honeypotId: config.honeypotId,
      });
    }

    // Store locally when API is unreachable
    storeAttackLocally(enhancedData);

    throw error;
  }
}

/**
 * Überprüft, ob ein Bericht gedrosselt werden sollte
 * @param {string} ip IP-Adresse
 * @param {string} attackType Angriffstyp
 * @returns {boolean} True, wenn gedrosselt werden sollte
 */
function shouldThrottleReport(ip, attackType) {
  // Wenn IP nicht im Cache, nicht drosseln
  if (!reportedIPCache.has(ip)) {
    return false;
  }

  const cacheInfo = reportedIPCache.get(ip);
  const now = Date.now();

  // Cache-Eintrag abgelaufen
  if (now - cacheInfo.timestamp > IP_CACHE_TTL) {
    reportedIPCache.delete(ip);
    return false;
  }

  // Wenn wir nach Angriffstyp drosseln, prüfen, ob dieser Typ neu ist
  if (REPORT_TYPES_THROTTLE && !cacheInfo.attack_types.has(attackType)) {
    return false; // Neuer Angriffstyp, nicht drosseln
  }

  // Check if we've configured unique types only
  if (
    process.env.REPORT_UNIQUE_TYPES_ONLY === "true" &&
    cacheInfo.attack_types.has(attackType)
  ) {
    return true; // Already reported this type, throttle it
  }

  // Prüfen, ob maximale Anzahl an Berichten erreicht ist
  return (
    cacheInfo.reported_count >=
    (parseInt(process.env.MAX_REPORTS_PER_IP) || MAX_REPORTS_PER_IP_PER_HOUR)
  );
}

/**
 * Aktualisiert den Cache mit einem neuen Bericht
 * @param {string} ip IP-Adresse
 * @param {string} attackType Angriffstyp
 */
function updateReportCache(ip, attackType) {
  const now = Date.now();

  if (!reportedIPCache.has(ip)) {
    reportedIPCache.set(ip, {
      timestamp: now,
      attack_types: new Set([attackType]),
      reported_count: 1,
    });
    return;
  }

  const cacheInfo = reportedIPCache.get(ip);

  // Wenn Cache-Eintrag abgelaufen, zurücksetzen
  if (now - cacheInfo.timestamp > IP_CACHE_TTL) {
    reportedIPCache.set(ip, {
      timestamp: now,
      attack_types: new Set([attackType]),
      reported_count: 1,
    });
    return;
  }

  // Sonst aktualisieren
  cacheInfo.attack_types.add(attackType);
  cacheInfo.reported_count++;
}

/**
 * Löscht abgelaufene Cache-Einträge
 */
function cleanupReportCache() {
  const now = Date.now();
  for (const [ip, info] of reportedIPCache.entries()) {
    if (now - info.timestamp > IP_CACHE_TTL) {
      reportedIPCache.delete(ip);
    }
  }
}

// Cache bereinigen alle 10 Minuten
setInterval(cleanupReportCache, 600000);

// Helper function to store attacks locally when API is unreachable
function storeAttackLocally(attackData) {
  const fs = require("fs");
  const path = require("path");

  try {
    const logsDir = path.join(process.cwd(), "logs");
    const offlineAttacksFile = path.join(logsDir, "offline_attacks.json");

    // Create logs directory if it doesn't exist
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }

    // Create an entry with timestamp
    const entry = {
      ...attackData,
      stored_at: new Date().toISOString(),
      pending_upload: true,
    };

    // Load existing or create new array
    let attacks = [];
    if (fs.existsSync(offlineAttacksFile)) {
      const content = fs.readFileSync(offlineAttacksFile, "utf8");
      attacks = JSON.parse(content);
    }

    // Add new entry
    attacks.push(entry);

    // Write back to file
    fs.writeFileSync(offlineAttacksFile, JSON.stringify(attacks, null, 2));
  } catch (err) {
    console.error("Error storing attack locally:", err.message);
  }
}

// Function to upload stored offline attacks
async function uploadStoredAttacks(config, logger) {
  const log = logger || console;
  const fs = require("fs");
  const path = require("path");

  const offlineAttacksFile = path.join(
    process.cwd(),
    "logs",
    "offline_attacks.json"
  );

  if (!fs.existsSync(offlineAttacksFile)) {
    return { uploaded: 0, status: "no_pending_attacks" };
  }

  try {
    const content = fs.readFileSync(offlineAttacksFile, "utf8");
    const attacks = JSON.parse(content);

    if (attacks.length === 0) {
      return { uploaded: 0, status: "no_pending_attacks" };
    }

    log.info(
      `Versuche ${attacks.length} offline gespeicherte Angriffe hochzuladen...`
    );

    let uploadedCount = 0;
    const remainingAttacks = [];

    // Create the same custom axios instance here
    const instance = axios.create({
      timeout: 5000,
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      decompress: true,
      maxRedirects: 5,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    });

    for (const attack of attacks) {
      if (!attack.pending_upload) continue;

      try {
        // Make sure the attack has the standardized format
        const enhancedAttack =
          attack.attack_type.startsWith("SQLI_") ||
          attack.attack_type.startsWith("XSS_") ||
          attack.attack_type.startsWith("PORT_")
            ? attack
            : enhanceAttackData(attack);

        // Format evidence as array if it's a string
        let evidence = enhancedAttack.evidence;
        if (typeof evidence === "string") {
          try {
            // Try to parse JSON string
            const parsedEvidence = JSON.parse(evidence);
            evidence = Array.isArray(parsedEvidence)
              ? parsedEvidence
              : [evidence];
          } catch (e) {
            // If not valid JSON, use as a single element array
            evidence = [evidence];
          }
        } else if (evidence && !Array.isArray(evidence)) {
          // Convert non-array objects to array
          evidence = [JSON.stringify(evidence)];
        }

        // Prepare the request body according to the API specification
        const requestBody = {
          ip_address: enhancedAttack.ip_address,
          attack_type: enhancedAttack.attack_type,
          description: enhancedAttack.description,
          evidence: evidence,
          severity: enhancedAttack.severity,
          category: enhancedAttack.category,
          source: "honeypot",
        };

        // Use the instance for the request
        await instance.post(
          `${config.apiEndpoint}/honeypot/report-ip`,
          requestBody,
          {
            params: { api_key: config.apiKey },
          }
        );

        uploadedCount++;
        attack.pending_upload = false;
        attack.uploaded_at = new Date().toISOString();
      } catch (error) {
        log.error(`Fehler beim Upload von offline Attack: ${error.message}`);
        remainingAttacks.push(attack);
      }
    }

    // Write remaining attacks back to file
    fs.writeFileSync(
      offlineAttacksFile,
      JSON.stringify(
        attacks.filter((a) => a.pending_upload),
        null,
        2
      )
    );

    return {
      uploaded: uploadedCount,
      remaining: remainingAttacks.length,
      status: "upload_completed",
    };
  } catch (error) {
    log.error("Fehler beim Verarbeiten der offline Angriffe", {
      error: error.message,
    });
    return { error: error.message, status: "upload_failed" };
  }
}

// Funktion zum Überprüfen, ob eine IP-Adresse bereits als verdächtig bekannt ist
async function checkIP(config, ipAddress, logger) {
  // Optionaler logger-Parameter für mehr Details
  const log = logger || console;

  try {
    if (config.debugMode) {
      log.debug(`Überprüfe IP ${ipAddress} bei der API...`);
    }

    // Create a custom axios instance for this request with specific config
    const instance = axios.create({
      timeout: 5000, // 5 seconds timeout
      headers: {
        Accept: "application/json",
      },
    });

    const response = await instance.get(`${config.apiEndpoint}/get`, {
      params: {
        api_key: config.apiKey,
        ip: ipAddress,
      },
    });

    return {
      success: true,
      data: response.data,
      status: response.status,
    };
  } catch (error) {
    log.error(`Fehler beim Überprüfen der IP ${ipAddress}`, {
      error: error.message,
      statusCode: error.response?.status,
    });

    return {
      success: false,
      error: error.message,
      status: error.response?.status,
      data: error.response?.data,
    };
  }
}

// Funktion zum Testen der API-Verbindung
async function testApiConnection(config, logger) {
  // Optionaler logger-Parameter für mehr Details
  const log = logger || console;

  try {
    log.debug("Teste API-Verbindung...");

    // Create a custom axios instance for this request with specific config
    const instance = axios.create({
      timeout: 5000, // 5 seconds timeout
      headers: {
        Accept: "application/json",
      },
    });

    const response = await instance.get(`${config.apiEndpoint}/ping`, {
      params: {
        api_key: config.apiKey,
      },
    });

    return {
      success: true,
      data: response.data,
      status: response.status,
      message: "API-Verbindung erfolgreich",
    };
  } catch (error) {
    log.error("API-Verbindungstest fehlgeschlagen", {
      error: error.message,
      statusCode: error.response?.status,
    });

    return {
      success: false,
      error: error.message,
      status: error.response?.status,
      data: error.response?.data,
    };
  }
}

// Diagnostik-Funktion für API-Probleme
function getLastHeartbeatInfo() {
  return {
    request: lastHeartbeatRequest,
    response: lastHeartbeatResponse,
    error: lastHeartbeatError,
    timestamp: new Date().toISOString(),
  };
}

// Gibt Statistiken zum IP-Reporting-Cache zurück
function getReportCacheStats() {
  const stats = {
    total_cached_ips: reportedIPCache.size,
    ip_details: {},
  };

  // Begrenzte Details für die TOP 10 am häufigsten gemeldeten IPs
  const sortedEntries = [...reportedIPCache.entries()]
    .sort((a, b) => b[1].reported_count - a[1].reported_count)
    .slice(0, 10);

  for (const [ip, info] of sortedEntries) {
    stats.ip_details[ip] = {
      attack_types: [...info.attack_types],
      reported_count: info.reported_count,
      first_seen: new Date(info.timestamp).toISOString(),
    };
  }

  return stats;
}

module.exports = {
  sendHeartbeat,
  reportAttack,
  checkIP,
  testApiConnection,
  getLastHeartbeatInfo,
  uploadStoredAttacks,
  storeAttackLocally,
  getReportCacheStats,
  // Export für Tests/Debugging
  clearReportCache: () => reportedIPCache.clear(),
};
