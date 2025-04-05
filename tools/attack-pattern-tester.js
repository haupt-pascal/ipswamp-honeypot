/**
 * Attack Pattern Tester
 *
 * This script tests how our different attack types get mapped to the
 * standardized types used by the scoring system.
 */

const {
  enhanceAttackData,
  ATTACK_TYPE_MAPPING,
  ATTACK_PATTERNS,
} = require("../src/utils/attack-pattern-adapter");

// Cool terminal colors for nicer output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
};

// Some sample attacks to test the mapping with
const attackSamples = [
  // HTTP Module attacks
  {
    ip_address: "192.168.1.10",
    attack_type: "sql_injection",
    description: "SQL injection attempt detected",
  },
  {
    ip_address: "192.168.1.11",
    attack_type: "xss_attack",
    description: "Cross-site scripting attempt",
  },
  {
    ip_address: "192.168.1.12",
    attack_type: "path_traversal",
    description: "Directory traversal attempt",
    evidence: ["../../../etc/passwd"],
  },
  {
    ip_address: "192.168.1.13",
    attack_type: "command_injection",
    description: "OS command injection attempt",
  },
  {
    ip_address: "192.168.1.14",
    attack_type: "directory_listing",
    description: "Attempt to list directories",
  },
  {
    ip_address: "192.168.1.15",
    attack_type: "admin_bruteforce",
    description: "Admin login bruteforce",
  },
  {
    ip_address: "192.168.1.16",
    attack_type: "suspicious_request",
    description: "Suspicious query parameters",
    evidence: ["union select * from users"],
  },
  {
    ip_address: "192.168.1.17",
    attack_type: "bot_request",
    description: "Fake crawler detected",
  },

  // SSH Module attacks
  {
    ip_address: "192.168.1.20",
    attack_type: "ssh_bruteforce",
    description: "SSH login bruteforce",
  },
  {
    ip_address: "192.168.1.21",
    attack_type: "ssh_invalid_user",
    description: "SSH login with invalid username",
  },

  // FTP Module attacks
  {
    ip_address: "192.168.1.30",
    attack_type: "ftp_bruteforce",
    description: "FTP login bruteforce",
  },
  {
    ip_address: "192.168.1.31",
    attack_type: "ftp_invalid_user",
    description: "FTP login with invalid username",
  },

  // Generic attacks
  {
    ip_address: "192.168.1.40",
    attack_type: "port_scan",
    description: "Port scanning activity detected",
  },
  {
    ip_address: "192.168.1.41",
    attack_type: "honeypot_hit",
    description: "Generic honeypot access",
  },
  {
    ip_address: "192.168.1.42",
    attack_type: "credential_stuffing",
    description: "Credential stuffing attack",
  },
  {
    ip_address: "192.168.1.43",
    attack_type: "dos_attempt",
    description: "Possible DoS attempt",
  },

  // Unknown/unusual types
  {
    ip_address: "192.168.1.50",
    attack_type: "unknown_attack",
    description: "Unknown attack type",
  },
  {
    ip_address: "192.168.1.51",
    attack_type: "",
    description: "Empty attack type",
  },
  {
    ip_address: "192.168.1.52",
    attack_type: null,
    description: "Null attack type",
  },
];

// Test the mapping function
console.log(
  `${colors.bright}${colors.cyan}Attack Pattern Mapping Tester${colors.reset}`
);
console.log(
  `${colors.dim}Testing mapping of honeypot attack types to scoring system types${colors.reset}\n`
);

console.log(`${colors.bright}Mapped Attack Types:${colors.reset}`);
console.log("----------------------------------------");

// Process each sample
attackSamples.forEach((sample) => {
  const enhanced = enhanceAttackData(sample);

  console.log(
    `${colors.bright}Original:${colors.reset} ${sample.attack_type || "N/A"}`
  );
  console.log(
    `${colors.bright}Mapped to:${colors.reset} ${colors.green}${enhanced.attack_type}${colors.reset}`
  );
  console.log(
    `${colors.bright}Severity:${colors.reset} ${enhanced.severity} / 5`
  );
  console.log(`${colors.bright}Category:${colors.reset} ${enhanced.category}`);
  console.log(
    `${colors.bright}Base Score:${colors.reset} ${enhanced.metadata.baseScore}`
  );
  console.log("----------------------------------------");
});

// Count mapped types
const mappedCount = Object.keys(ATTACK_TYPE_MAPPING).length;
const patternCount = Object.keys(ATTACK_PATTERNS).length;

console.log(`\n${colors.bright}Summary:${colors.reset}`);
console.log(
  `${colors.bright}Total internal attack types mapped:${colors.reset} ${mappedCount}`
);
console.log(
  `${colors.bright}Total standardized attack patterns:${colors.reset} ${patternCount}`
);

console.log(`\n${colors.bright}${colors.cyan}Testing complete!${colors.reset}`);
