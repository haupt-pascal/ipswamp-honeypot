// API-Service für die Kommunikation mit dem Backend
const axios = require("axios");

// Speichere die letzte Heartbeat-Anfrage und -Antwort für Debugging
let lastHeartbeatRequest = null;
let lastHeartbeatResponse = null;
let lastHeartbeatError = null;

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

    const response = await axios({
      ...requestConfig,
      timeout: 10000, // 10 Sekunden Timeout
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

  // Check if we're in offline mode
  if (config.offlineMode) {
    log.info("Offline-Modus: Angriff lokal gespeichert", {
      attack_type: attackData.attack_type,
      ip_address: attackData.ip_address,
    });
    storeAttackLocally(attackData);
    return { status: "stored_locally", timestamp: new Date().toISOString() };
  }

  try {
    if (config.debugMode) {
      log.debug("Melde Angriff an API", {
        endpoint: `${config.apiEndpoint}/honeypot/report-ip`,
        type: attackData.attack_type,
      });
    }

    // Format evidence as array if it's a string
    let evidence = attackData.evidence;
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
      ip_address: attackData.ip_address,
      attack_type: attackData.attack_type,
      description: attackData.description,
      evidence: evidence,
    };

    // Use the new endpoint with properly formatted body
    const response = await axios.post(
      `${config.apiEndpoint}/honeypot/report-ip`,
      requestBody,
      {
        params: {
          api_key: config.apiKey,
        },
        timeout: 5000, // 5 Sekunden Timeout
      }
    );

    log.debug("Angriff erfolgreich gemeldet", {
      status: response.status,
      attack_type: attackData.attack_type,
      score: response.data?.current_score,
      ip_id: response.data?.ip_id,
    });

    return response.data;
  } catch (error) {
    // More detailed error logging
    const errorDetails = {
      error: error.message,
      attackType: attackData.attack_type,
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
    storeAttackLocally(attackData);

    throw error;
  }
}

// Helper function to store attacks locally when API is unreachable
function storeAttackLocally(attackData) {
  const fs = require("fs");
  const path = require("path");

  try {
    const logsDir = path.join(process.cwd(), "logs");
    const offlineAttacksFile = path.join(logsDir, "offline_attacks.json");

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

    for (const attack of attacks) {
      if (!attack.pending_upload) continue;

      try {
        // Format evidence as array if it's a string
        let evidence = attack.evidence;
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
          ip_address: attack.ip_address,
          attack_type: attack.attack_type,
          description: attack.description,
          evidence: evidence,
        };

        // Use the new endpoint with properly formatted body
        await axios.post(
          `${config.apiEndpoint}/honeypot/report-ip`,
          requestBody,
          {
            params: { api_key: config.apiKey },
            timeout: 5000,
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
  const log = logger || console;

  try {
    const response = await axios.get(`${config.apiEndpoint}/get`, {
      params: {
        api_key: config.apiKey,
        ip: ipAddress,
      },
      timeout: 5000, // 5 Sekunden Timeout
    });

    return response.data;
  } catch (error) {
    log.error("Fehler beim Überprüfen der IP-Adresse", {
      error: error.message,
      ip: ipAddress,
      response: error.response
        ? {
            status: error.response.status,
            data: error.response.data,
          }
        : null,
    });
    throw error;
  }
}

// Funktion zum Testen der API-Verbindung
async function testApiConnection(config, logger) {
  const log = logger || console;

  log.info("Teste API-Verbindung...");

  try {
    // Versuche eine einfache Anfrage an den API-Server
    const response = await axios.get(`${config.apiEndpoint}/ping`, {
      params: {
        api_key: config.apiKey,
      },
      timeout: 5000,
    });

    log.info("API-Verbindung erfolgreich", {
      endpoint: `${config.apiEndpoint}/ping`,
      status: response.status,
      data: response.data,
    });

    return {
      success: true,
      status: response.status,
      data: response.data,
    };
  } catch (error) {
    log.error("API-Verbindungstest fehlgeschlagen", {
      error: error.message,
      endpoint: `${config.apiEndpoint}/ping`,
      response: error.response
        ? {
            status: error.response.status,
            data: error.response.data,
          }
        : null,
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

module.exports = {
  sendHeartbeat,
  reportAttack,
  checkIP,
  testApiConnection,
  getLastHeartbeatInfo,
  uploadStoredAttacks,
  storeAttackLocally,
};
