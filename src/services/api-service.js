// API service for sending reports to the backend
const axios = require("axios");
const fs = require("fs");
const path = require("path");

// Import the attack pattern adapter
const { enhanceAttackData } = require("../utils/attack-pattern-adapter");

// Store heartbeat data for diagnostics
let lastHeartbeatRequest = null;
let lastHeartbeatResponse = null;
let lastHeartbeatError = null;

// Cache for reported IPs to avoid spamming the API
// Format: { ip_address: { timestamp: Date, attack_types: Set, reported_count: number } }
const reportedIPCache = new Map();

// Settings for IP throttling
const IP_CACHE_TTL = 3600000; // 1 hour
const MAX_REPORTS_PER_IP_PER_HOUR = 10;
const REPORT_TYPES_THROTTLE = true; // Only report new attack types for already reported IPs

// Clear stored attacks when the module starts
// This prevents sending old attacks when the container restarts
clearStoredAttacks();

/**
 * Clears all stored attacks
 */
function clearStoredAttacks() {
  storedAttacks = [];
  // Clear the IP cache
  reportedIPCache.clear();
  // Also delete the stored attacks file if it exists
  try {
    const storedAttacksPath = path.join(
      process.cwd(),
      "logs",
      "stored_attacks.json"
    );
    if (fs.existsSync(storedAttacksPath)) {
      fs.unlinkSync(storedAttacksPath);
    }
  } catch (error) {
    // Silent fail if we can't delete the file
    console.error("Failed to delete stored attacks file:", error.message);
  }
}

// Send a heartbeat to register with the API
async function sendHeartbeat(config, logger) {
  // Optional logger parameter for more details
  const log = logger || console;

  // Create request object for debugging
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
    params: { ...requestConfig.params, api_key: "***redacted***" }, // Hide API key in logs
    data: requestConfig.data,
    headers: requestConfig.headers,
  };

  try {
    // Debug logging before request
    if (config.debugMode) {
      log.debug("Sending heartbeat request", {
        endpoint: requestConfig.url,
        honeypot_id: requestData.honeypot_id,
        headers: requestConfig.headers,
      });
    }

    // Create a custom axios instance for this request
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

    // Send the request
    const response = await instance({
      url: requestConfig.url,
      method: requestConfig.method,
      params: requestConfig.params,
      data: requestConfig.data,
      headers: requestConfig.headers,
    });

    // Store response for debugging
    lastHeartbeatResponse = {
      timestamp: new Date().toISOString(),
      status: response.status,
      statusText: response.statusText,
      data: response.data,
      headers: response.headers,
    };

    lastHeartbeatError = null;

    // Debug logging after successful request
    if (config.debugMode) {
      log.debug("Heartbeat response received", {
        status: response.status,
        data: response.data,
      });
    }

    return response.data;
  } catch (error) {
    // Capture detailed error info
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

    // More detailed error logging based on type
    if (error.response) {
      // The server responded with an error code
      log.error(
        `Heartbeat error: Server responded with status ${error.response.status}`,
        {
          status: error.response.status,
          statusText: error.response.statusText,
          data: error.response.data,
        }
      );
    } else if (error.request) {
      // The request was made but no response received
      log.error("Heartbeat error: No response from server", {
        message: error.message,
        code: error.code,
      });
    } else {
      // Something happened in setup
      log.error("Heartbeat error: Request setup failed", {
        message: error.message,
      });
    }

    throw error;
  }
}

// Report detected attacks to the API
async function reportAttack(config, attackData, logger) {
  const log = logger || console;

  // Enhance attack data with standardized types and severity
  const enhancedData = enhanceAttackData(attackData);

  // Get IP and attack type
  const { ip_address, attack_type } = enhancedData;

  // Check if we should throttle this report
  if (shouldThrottleReport(ip_address, attack_type)) {
    if (config.debugMode) {
      log.debug(
        `IP ${ip_address} was recently reported with attack type ${attack_type} - throttling report`,
        {
          ip: ip_address,
          attack_type: attack_type,
          original_type: attackData.attack_type,
          cache_info: reportedIPCache.get(ip_address),
        }
      );
    }

    // Still increment counter even if not reporting
    updateReportCache(ip_address, attack_type);

    // Store locally if configured to do so
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

  // Update the cache with this report
  updateReportCache(ip_address, attack_type);

  // Check if we're in offline mode
  if (config.offlineMode) {
    log.info("Offline mode: Attack stored locally", {
      attack_type: enhancedData.attack_type,
      ip_address: enhancedData.ip_address,
    });
    storeAttackLocally(enhancedData);
    return { status: "stored_locally", timestamp: new Date().toISOString() };
  }

  try {
    if (config.debugMode) {
      log.debug("Reporting attack to API", {
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
        // If not valid JSON, use as single element array
        evidence = [evidence];
      }
    } else if (evidence && !Array.isArray(evidence)) {
      // Convert non-array objects to array
      evidence = [JSON.stringify(evidence)];
    }

    // Prepare the request body for the API
    const requestBody = {
      ip_address: enhancedData.ip_address,
      attack_type: enhancedData.attack_type,
      description: enhancedData.description,
      evidence: evidence,
      severity: enhancedData.severity,
      category: enhancedData.category,
      source: "honeypot",
    };

    // Create a custom axios instance for this request
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

    // Send the request
    const response = await instance.post(
      `${config.apiEndpoint}/honeypot/report-ip`,
      requestBody,
      {
        params: {
          api_key: config.apiKey,
        },
      }
    );

    log.debug("Attack successfully reported", {
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

    log.error("Error reporting attack", errorDetails);

    // If we get 403 forbidden, could be an API key issue
    if (error.response && error.response.status === 403) {
      log.warn("API key doesn't have permission for attack reporting", {
        honeypotId: config.honeypotId,
      });
    }

    // Store locally when API is unreachable
    storeAttackLocally(enhancedData);

    throw error;
  }
}

/**
 * Checks if a report should be throttled
 * @param {string} ip IP address
 * @param {string} attackType Attack type
 * @returns {boolean} True if should be throttled
 */
function shouldThrottleReport(ip, attackType) {
  // If IP not in cache, don't throttle
  if (!reportedIPCache.has(ip)) {
    return false;
  }

  const cacheInfo = reportedIPCache.get(ip);
  const now = Date.now();

  // Cache entry expired
  if (now - cacheInfo.timestamp > IP_CACHE_TTL) {
    reportedIPCache.delete(ip);
    return false;
  }

  // If we throttle by attack type, check if this type is new
  if (REPORT_TYPES_THROTTLE && !cacheInfo.attack_types.has(attackType)) {
    return false; // New attack type, don't throttle
  }

  // Check if we've configured unique types only
  if (
    process.env.REPORT_UNIQUE_TYPES_ONLY === "true" &&
    cacheInfo.attack_types.has(attackType)
  ) {
    return true; // Already reported this type, throttle it
  }

  // Check if max reports reached
  return (
    cacheInfo.reported_count >=
    (parseInt(process.env.MAX_REPORTS_PER_IP) || MAX_REPORTS_PER_IP_PER_HOUR)
  );
}

/**
 * Updates the cache with a new report
 * @param {string} ip IP address
 * @param {string} attackType Attack type
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

  // If cache expired, reset it
  if (now - cacheInfo.timestamp > IP_CACHE_TTL) {
    reportedIPCache.set(ip, {
      timestamp: now,
      attack_types: new Set([attackType]),
      reported_count: 1,
    });
    return;
  }

  // Otherwise update
  cacheInfo.attack_types.add(attackType);
  cacheInfo.reported_count++;
}

/**
 * Cleans up expired cache entries
 */
function cleanupReportCache() {
  const now = Date.now();
  for (const [ip, info] of reportedIPCache.entries()) {
    if (now - info.timestamp > IP_CACHE_TTL) {
      reportedIPCache.delete(ip);
    }
  }
}

// Clean up cache every 10 minutes
setInterval(cleanupReportCache, 600000);

// Store attacks locally when API is unreachable
function storeAttackLocally(attackData) {
  const fs = require("fs");
  const path = require("path");

  try {
    const logsDir = path.join(process.cwd(), "logs");
    const offlineAttacksFile = path.join(logsDir, "offline_attacks.json");

    // Create logs directory if needed
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }

    // Add timestamp to the entry
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

// Upload stored offline attacks
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
      `Attempting to upload ${attacks.length} offline stored attacks...`
    );

    let uploadedCount = 0;
    const remainingAttacks = [];

    // Create an axios instance
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
            // If not valid JSON, use as single element array
            evidence = [evidence];
          }
        } else if (evidence && !Array.isArray(evidence)) {
          // Convert non-array objects to array
          evidence = [JSON.stringify(evidence)];
        }

        // Prepare request body
        const requestBody = {
          ip_address: enhancedAttack.ip_address,
          attack_type: enhancedAttack.attack_type,
          description: enhancedAttack.description,
          evidence: evidence,
          severity: enhancedAttack.severity,
          category: enhancedAttack.category,
          source: "honeypot",
        };

        // Send request
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
        log.error(`Error uploading offline attack: ${error.message}`);
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
    log.error("Error processing offline attacks", {
      error: error.message,
    });
    return { error: error.message, status: "upload_failed" };
  }
}

// Check if an IP is already known as suspicious
async function checkIP(config, ipAddress, logger) {
  // Optional logger parameter
  const log = logger || console;

  try {
    if (config.debugMode) {
      log.debug(`Checking IP ${ipAddress} with API...`);
    }

    // Create a custom axios instance
    const instance = axios.create({
      timeout: 5000, // 5 second timeout
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
    log.error(`Error checking IP ${ipAddress}`, {
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

// Test API connection
async function testApiConnection(config, logger) {
  // Optional logger parameter
  const log = logger || console;

  try {
    log.debug("Testing API connection...");

    // Create a custom axios instance
    const instance = axios.create({
      timeout: 5000, // 5 second timeout
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
      message: "API connection successful",
    };
  } catch (error) {
    log.error("API connection test failed", {
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

// Get last heartbeat info for diagnostics
function getLastHeartbeatInfo() {
  return {
    request: lastHeartbeatRequest,
    response: lastHeartbeatResponse,
    error: lastHeartbeatError,
    timestamp: new Date().toISOString(),
  };
}

// Get stats about the IP reporting cache
function getReportCacheStats() {
  const stats = {
    total_cached_ips: reportedIPCache.size,
    ip_details: {},
  };

  // Show details for top 10 most reported IPs
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
  // Export for tests/debugging
  clearReportCache: () => reportedIPCache.clear(),
  clearStoredAttacks,
};
