/**
 * Attack Pattern Adapter
 *
 * Maps honeypot attack classifications to standardized types compatible with
 * the scoring system. This ensures consistent scoring across different sources.
 */

// Attack pattern mapping based on the scoring system
const ATTACK_PATTERNS = {
  // Low severity attacks (1-5)
  SUSPICIOUS_USER_AGENT: {
    type: "suspicious_user_agent",
    baseScore: 2,
    description: "Unusual or known malicious user agent detected",
    category: "reconnaissance",
  },
  DIRECTORY_LISTING_ATTEMPT: {
    type: "directory_listing",
    baseScore: 3,
    description: "Attempt to access directory listings",
    category: "reconnaissance",
  },
  EXCESSIVE_404: {
    type: "excessive_404",
    baseScore: 3,
    description: "Unusually high number of 404 errors",
    category: "reconnaissance",
  },
  SUSPICIOUS_QUERY_STRING: {
    type: "suspicious_query",
    baseScore: 4,
    description: "Query strings with suspicious patterns",
    category: "reconnaissance",
  },
  FAKE_CRAWLER: {
    type: "fake_crawler",
    baseScore: 4,
    description: "Bot claiming to be a legitimate crawler but isn't",
    category: "reconnaissance",
  },

  // Medium-low severity attacks (6-10)
  RATE_LIMIT_BREACH: {
    type: "rate_limit_breach",
    baseScore: 6,
    description: "Exceeded normal request rate thresholds",
    category: "abuse",
  },
  API_ABUSE: {
    type: "api_abuse",
    baseScore: 7,
    description: "Abusive patterns of API usage",
    category: "abuse",
  },
  PORT_SCAN: {
    type: "port_scan",
    baseScore: 8,
    description: "Systematic port scanning activity",
    category: "reconnaissance",
  },
  COMMENT_SPAM: {
    type: "comment_spam",
    baseScore: 8,
    description: "Automated comment/form spam",
    category: "abuse",
  },
  HONEYPOT: {
    type: "honeypot",
    baseScore: 9,
    description: "Activity detected in honeypot",
    category: "general",
  },

  // Medium severity attacks (11-15)
  CREDENTIAL_STUFFING: {
    type: "credential_stuffing",
    baseScore: 11,
    description: "Multiple login attempts with different credentials",
    category: "authentication",
  },
  XSS_ATTEMPT: {
    type: "xss_attempt",
    baseScore: 12,
    description: "Cross-site scripting attempt detected",
    category: "injection",
  },
  CSRF_ATTEMPT: {
    type: "csrf_attempt",
    baseScore: 12,
    description: "Cross-site request forgery attempt",
    category: "authentication",
  },
  PATH_TRAVERSAL: {
    type: "path_traversal",
    baseScore: 13,
    description: "Directory traversal attempt",
    category: "injection",
  },
  AUTHENTICATION_BREACH: {
    type: "auth_breach",
    baseScore: 15,
    description: "Multiple failed authentication attempts",
    category: "authentication",
  },

  // Medium-high severity attacks (16-20)
  SQLI_ATTEMPT: {
    type: "sqli_attempt",
    baseScore: 16,
    description: "SQL injection attempt detected",
    category: "injection",
  },
  SSH_BRUTEFORCE: {
    type: "ssh_bruteforce",
    baseScore: 18,
    description: "Brute force attacks against SSH",
    category: "authentication",
  },
  HTTP_FLOOD: {
    type: "http_flood",
    baseScore: 18,
    description: "HTTP request flooding",
    category: "dos",
  },
  MAIL_SPAM: {
    type: "mail_spam",
    baseScore: 19,
    description: "Email spam originating from IP",
    category: "abuse",
  },
  COMMAND_INJECTION: {
    type: "command_injection",
    baseScore: 20,
    description: "Command injection attempt detected",
    category: "injection",
  },

  // High severity attacks (21-30)
  HTTP_INJECTION: {
    type: "http_injection",
    baseScore: 22,
    description: "Injection attempts via HTTP parameters",
    category: "injection",
  },
  DATA_EXFILTRATION: {
    type: "data_exfiltration",
    baseScore: 25,
    description: "Attempted data exfiltration detected",
    category: "intrusion",
  },
  BOTNET_ACTIVITY: {
    type: "botnet_activity",
    baseScore: 28,
    description: "Communication patterns consistent with botnet activity",
    category: "malware",
  },

  // Very high severity attacks (31-50)
  RANSOMWARE_DISTRIBUTION: {
    type: "ransomware",
    baseScore: 35,
    description: "Distributing ransomware or other malware",
    category: "malware",
  },
  DDOS_ATTACK: {
    type: "ddos",
    baseScore: 40,
    description: "Participating in distributed denial of service attacks",
    category: "dos",
  },
  TARGETED_ATTACK: {
    type: "targeted_attack",
    baseScore: 45,
    description: "Evidence of targeted attack against specific systems",
    category: "intrusion",
  },

  // Other/Manual categories
  MANUAL: {
    type: "manual",
    baseScore: 15,
    description: "Manually reported malicious activity",
    category: "general",
  },
  TOR_EXIT_NODE: {
    type: "tor_exit",
    baseScore: 10,
    description: "Known Tor exit node",
    category: "anonymity",
  },
  PROXY_ABUSE: {
    type: "proxy_abuse",
    baseScore: 8,
    description: "Abuse through anonymous proxy",
    category: "anonymity",
  },
  VPN_ABUSE: {
    type: "vpn_abuse",
    baseScore: 7,
    description: "Abuse through VPN service",
    category: "anonymity",
  },
};

// Mapping from internal attack types to standardized types
const ATTACK_TYPE_MAPPING = {
  // HTTP module attack types
  sql_injection: "SQLI_ATTEMPT",
  sql_injection_attempt: "SQLI_ATTEMPT",
  xss_attack: "XSS_ATTEMPT",
  xss: "XSS_ATTEMPT",
  path_traversal: "PATH_TRAVERSAL",
  directory_traversal: "PATH_TRAVERSAL",
  command_injection: "COMMAND_INJECTION",
  os_command_injection: "COMMAND_INJECTION",
  directory_listing: "DIRECTORY_LISTING_ATTEMPT",
  directory_scan: "DIRECTORY_LISTING_ATTEMPT",
  admin_bruteforce: "AUTHENTICATION_BREACH",
  login_attempt: "AUTHENTICATION_BREACH",
  suspicious_request: "SUSPICIOUS_QUERY_STRING",
  strange_query: "SUSPICIOUS_QUERY_STRING",
  bot_request: "FAKE_CRAWLER",
  fake_bot: "FAKE_CRAWLER",
  spam_attempt: "COMMENT_SPAM",
  form_spam: "COMMENT_SPAM",
  rate_limit: "RATE_LIMIT_BREACH",
  too_many_requests: "RATE_LIMIT_BREACH",
  api_abuse: "API_ABUSE",
  management_access: "AUTHENTICATION_BREACH",
  admin_portal_access: "AUTHENTICATION_BREACH",

  // SSH module attack types
  ssh_bruteforce: "SSH_BRUTEFORCE",
  ssh_invalid_user: "SSH_BRUTEFORCE",
  ssh_auth_failure: "SSH_BRUTEFORCE",

  // FTP module attack types
  ftp_bruteforce: "AUTHENTICATION_BREACH",
  ftp_invalid_user: "AUTHENTICATION_BREACH",
  ftp_auth_failure: "AUTHENTICATION_BREACH",

  // Mail server attack types
  smtp_auth_attempt: "AUTHENTICATION_BREACH",
  smtp_spam_attempt: "MAIL_SPAM",
  smtp_relay_attempt: "MAIL_SPAM",
  smtp_bulk_attempt: "MAIL_SPAM",
  smtp_scan: "PORT_SCAN",
  imap_bruteforce: "AUTHENTICATION_BREACH",
  imap_invalid_user: "AUTHENTICATION_BREACH",
  pop3_bruteforce: "AUTHENTICATION_BREACH",
  pop3_invalid_user: "AUTHENTICATION_BREACH",
  mail_auth_failure: "AUTHENTICATION_BREACH",
  mail_overflow_attempt: "BOTNET_ACTIVITY",
  email_harvesting: "SUSPICIOUS_QUERY_STRING",

  // MySQL attack types
  mysql_bruteforce: "AUTHENTICATION_BREACH",
  mysql_invalid_user: "AUTHENTICATION_BREACH",
  mysql_auth_failure: "AUTHENTICATION_BREACH",
  mysql_sqli_attempt: "SQLI_ATTEMPT",
  mysql_overflow_attempt: "HTTP_INJECTION",
  mysql_scan: "PORT_SCAN",

  // Generic honeypot attack types
  port_scan: "PORT_SCAN",
  port_probe: "PORT_SCAN",
  portscan: "PORT_SCAN",
  honeypot_hit: "HONEYPOT",
  honeypot_access: "HONEYPOT",
  credential_stuffing: "CREDENTIAL_STUFFING",
  password_spray: "CREDENTIAL_STUFFING",
  dos_attempt: "HTTP_FLOOD",
  flood_attack: "HTTP_FLOOD",
  http_flood: "HTTP_FLOOD",
  generic_attack: "MANUAL",
  suspicious_activity: "HONEYPOT",

  // Default fallback
  default: "HONEYPOT",
};

/**
 * Maps an internal attack type to a standardized type for the scoring system
 *
 * @param {string} internalType - The internal attack type used by the honeypot
 * @param {object} attackData - Additional attack data that might help determine the type
 * @returns {string} - The standardized attack type for the scoring system
 */
function mapAttackType(internalType, attackData = {}) {
  // Use lowercase for consistent mapping
  const lowerType = (internalType || "default").toLowerCase();

  // Special case handling based on additional data
  if (lowerType === "suspicious_request" && attackData.evidence) {
    const evidence = Array.isArray(attackData.evidence)
      ? attackData.evidence.join(" ").toLowerCase()
      : String(attackData.evidence).toLowerCase();

    // Check for specific patterns in the evidence
    if (
      evidence.includes("union select") ||
      evidence.includes("information_schema")
    ) {
      return "SQLI_ATTEMPT";
    }
    if (
      evidence.includes("script") &&
      (evidence.includes("alert") || evidence.includes("cookie"))
    ) {
      return "XSS_ATTEMPT";
    }
    if (evidence.includes("../") || evidence.includes("..%2f")) {
      return "PATH_TRAVERSAL";
    }
  }

  // Return the mapped type or default if not found
  return ATTACK_TYPE_MAPPING[lowerType] || ATTACK_TYPE_MAPPING["default"];
}

/**
 * Calculates severity level based on attack type and additional data
 *
 * @param {string} standardizedType - The standardized attack type
 * @param {object} attackData - Additional attack data
 * @returns {number} - Severity level from 1-5
 */
function calculateSeverity(standardizedType, attackData = {}) {
  // Base severity levels for different attack types based on the pattern base score
  const severityMap = {
    SQLI_ATTEMPT: 4,
    XSS_ATTEMPT: 3,
    PATH_TRAVERSAL: 3,
    COMMAND_INJECTION: 5,
    SSH_BRUTEFORCE: 4,
    AUTHENTICATION_BREACH: 3,
    HTTP_FLOOD: 4,
    DDOS_ATTACK: 5,
    PORT_SCAN: 2,
    HONEYPOT: 2,
    default: 2,
  };

  // Get base severity
  let severity = severityMap[standardizedType] || severityMap["default"];

  // Adjust based on evidence amount
  if (
    attackData.evidence &&
    Array.isArray(attackData.evidence) &&
    attackData.evidence.length > 3
  ) {
    severity = Math.min(5, severity + 1);
  }

  // Adjust based on frequency if available
  if (attackData.frequency && attackData.frequency > 10) {
    severity = Math.min(5, severity + 1);
  }

  return severity;
}

/**
 * Enhances attack data with standardized information for the API
 *
 * @param {object} attackData - Original attack data from honeypot
 * @returns {object} - Enhanced attack data with standardized fields
 */
function enhanceAttackData(attackData) {
  if (!attackData || typeof attackData !== "object") {
    return attackData;
  }

  // Get the standardized type
  const standardizedType = mapAttackType(attackData.attack_type, attackData);

  // Calculate severity
  const severity = calculateSeverity(standardizedType, attackData);

  // Get base pattern data
  const pattern = ATTACK_PATTERNS[standardizedType] || ATTACK_PATTERNS.HONEYPOT;

  // Create enhanced object
  return {
    ...attackData,
    attack_type: standardizedType,
    source: standardizedType,
    severity: severity,
    category: pattern.category,
    // Add metadata to help with debugging and tracking
    metadata: {
      original_type: attackData.attack_type,
      baseScore: pattern.baseScore,
      description: pattern.description,
      enhanced_at: new Date().toISOString(),
    },
  };
}

/**
 * Gets details about a standardized attack type
 *
 * @param {string} standardizedType - The standardized attack type
 * @returns {object} - Attack pattern details
 */
function getAttackPatternDetails(standardizedType) {
  return ATTACK_PATTERNS[standardizedType] || ATTACK_PATTERNS.HONEYPOT;
}

module.exports = {
  mapAttackType,
  calculateSeverity,
  enhanceAttackData,
  getAttackPatternDetails,
  ATTACK_PATTERNS,
  ATTACK_TYPE_MAPPING,
};
