/**
 * API-Tester für IPSwamp Honeypot
 *
 * Dieses Tool hilft bei der Diagnose von API-Verbindungsproblemen.
 * Es führt verschiedene Tests durch, um die Verbindung zum Backend zu überprüfen.
 *
 * Verwendung:
 *   node tools/api-tester.js
 *
 * Optionen:
 *   --api-key=<key>       API-Schlüssel (Standard: aus .env oder Umgebungsvariablen)
 *   --api-endpoint=<url>  API-Endpunkt (Standard: aus .env oder Umgebungsvariablen)
 *   --honeypot-id=<id>    Honeypot-ID (Standard: aus .env oder Umgebungsvariablen)
 *   --verbose             Ausführliche Ausgabe
 */

const axios = require("axios");
const fs = require("fs");
const path = require("path");
const { promisify } = require("util");
const exec = promisify(require("child_process").exec);
const readline = require("readline");

// Lade Umgebungsvariablen aus .env, falls vorhanden
try {
  require("dotenv").config();
} catch (error) {
  // dotenv ist möglicherweise nicht installiert, kein Problem
}

// Parsen von Befehlszeilenargumenten
const args = process.argv.slice(2).reduce((acc, arg) => {
  if (arg.startsWith("--")) {
    const [key, value] = arg.slice(2).split("=");
    acc[key] = value || true;
  }
  return acc;
}, {});

// Konfiguration
const config = {
  apiKey:
    args["api-key"] ||
    process.env.API_KEY ||
    "e309bbf470b3e57d10082aa69325173e3c012e83ed6452a0d995bbb721c02f4a",
  apiEndpoint:
    args["api-endpoint"] ||
    process.env.API_ENDPOINT ||
    "https://api.ipswamp.com/api",
  honeypotId: args["honeypot-id"] || process.env.HONEYPOT_ID || "test",
  verbose: args.verbose || false,
};

// Farben für die Konsole
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

// Logging-Funktionen
const log = {
  info: (msg) => console.log(`${colors.blue}[INFO]${colors.reset} ${msg}`),
  success: (msg) =>
    console.log(`${colors.green}[SUCCESS]${colors.reset} ${msg}`),
  error: (msg) => console.log(`${colors.red}[ERROR]${colors.reset} ${msg}`),
  warn: (msg) => console.log(`${colors.yellow}[WARNING]${colors.reset} ${msg}`),
  debug: (msg) =>
    config.verbose && console.log(`${colors.dim}[DEBUG]${colors.reset} ${msg}`),
  title: (msg) =>
    console.log(
      `\n${colors.bright}${colors.cyan}${msg}${colors.reset}\n${"-".repeat(
        msg.length
      )}`
    ),
  json: (obj) => config.verbose && console.log(JSON.stringify(obj, null, 2)),
};

// Hilfsfunktion zum Ausführen eines Befehls
async function runCommand(command) {
  try {
    const { stdout, stderr } = await exec(command);
    return { success: true, stdout, stderr };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Hilfsfunktion für HTTP-Requests mit Timeout
async function makeRequest(options) {
  try {
    log.debug(`Sende Anfrage an ${options.url || options.endpoint}`);
    const response = await axios({
      url: options.url || options.endpoint,
      method: options.method || "GET",
      headers: options.headers || {
        "Content-Type": "application/json",
        "User-Agent": "IPSwamp-API-Tester/1.0",
      },
      params: options.params || {},
      data: options.data || {},
      timeout: options.timeout || 10000,
    });
    log.debug(`Status: ${response.status} ${response.statusText}`);
    return {
      success: true,
      status: response.status,
      data: response.data,
      headers: response.headers,
    };
  } catch (error) {
    if (error.response) {
      log.debug(
        `Status: ${error.response.status} ${error.response.statusText}`
      );
      return {
        success: false,
        status: error.response.status,
        error: error.message,
        data: error.response.data,
      };
    }
    return { success: false, error: error.message };
  }
}

// 1. Test: DNS-Auflösung
async function testDnsResolution() {
  log.title("Teste DNS-Auflösung");

  // Extrahiere Hostnamen aus dem API-Endpunkt
  const url = new URL(config.apiEndpoint);
  const hostname = url.hostname;

  log.info(`Löse Hostnamen auf: ${hostname}`);

  let dnsResult;
  if (process.platform === "win32") {
    dnsResult = await runCommand(`nslookup ${hostname}`);
  } else {
    dnsResult = await runCommand(`dig +short ${hostname} || host ${hostname}`);
  }

  if (dnsResult.success && dnsResult.stdout.trim()) {
    log.success(`DNS-Auflösung erfolgreich: ${hostname}`);
    log.debug(dnsResult.stdout);
    return true;
  } else {
    log.error(`DNS-Auflösung fehlgeschlagen für ${hostname}`);
    log.debug(dnsResult.stderr || dnsResult.error);
    return false;
  }
}

// 2. Test: Ping
async function testPing() {
  log.title("Teste Ping");

  const url = new URL(config.apiEndpoint);
  const hostname = url.hostname;

  log.info(`Ping ${hostname}...`);

  const pingCount = process.platform === "win32" ? "-n 3" : "-c 3";
  const pingResult = await runCommand(`ping ${pingCount} ${hostname}`);

  if (pingResult.success) {
    log.success(`Ping zu ${hostname} erfolgreich`);
    log.debug(pingResult.stdout);
    return true;
  } else {
    log.warn(
      `Ping zu ${hostname} fehlgeschlagen (kann normal sein, wenn ICMP blockiert ist)`
    );
    return false;
  }
}

// 3. Test: TCP-Verbindung
async function testTcpConnection() {
  log.title("Teste TCP-Verbindung");

  const url = new URL(config.apiEndpoint);
  const hostname = url.hostname;
  const port = url.port || (url.protocol === "https:" ? 443 : 80);

  log.info(`Teste TCP-Verbindung zu ${hostname}:${port}...`);

  let command;
  if (process.platform === "win32") {
    command = `powershell -Command "Test-NetConnection -ComputerName ${hostname} -Port ${port}"`;
  } else {
    command = `nc -zv ${hostname} ${port} -w 5 2>&1 || curl -s --connect-timeout 5 telnet://${hostname}:${port}`;
  }

  const tcpResult = await runCommand(command);

  if (
    tcpResult.success &&
    (tcpResult.stdout.includes("Succeeded") ||
      tcpResult.stdout.includes("open") ||
      tcpResult.stdout.includes("Connected"))
  ) {
    log.success(`TCP-Verbindung zu ${hostname}:${port} erfolgreich`);
    log.debug(tcpResult.stdout);
    return true;
  } else {
    log.error(`TCP-Verbindung zu ${hostname}:${port} fehlgeschlagen`);
    log.debug(tcpResult.stderr || tcpResult.stdout || tcpResult.error);
    return false;
  }
}

// 4. Test: HTTP-Basis
async function testHttpBase() {
  log.title("Teste HTTP-Basis");

  // Extrahiere Basis-URL aus dem API-Endpunkt
  const url = new URL(config.apiEndpoint);
  const baseUrl = `${url.protocol}//${url.host}`;

  log.info(`Sende HTTP-Anfrage an ${baseUrl}...`);

  const result = await makeRequest({
    url: baseUrl,
  });

  if (result.success) {
    log.success(
      `HTTP-Anfrage an ${baseUrl} erfolgreich (Status: ${result.status})`
    );
    return true;
  } else {
    log.error(`HTTP-Anfrage an ${baseUrl} fehlgeschlagen: ${result.error}`);
    return false;
  }
}

// 5. Test: API-Ping
async function testApiPing() {
  log.title("Teste API-Ping");

  const pingEndpoint = `${config.apiEndpoint}/ping`;
  log.info(`Sende API-Ping an ${pingEndpoint}...`);

  const result = await makeRequest({
    url: pingEndpoint,
    params: {
      api_key: config.apiKey,
    },
  });

  if (result.success) {
    log.success(`API-Ping erfolgreich (Status: ${result.status})`);
    log.debug(`Antwort: ${JSON.stringify(result.data)}`);
    return true;
  } else {
    log.error(`API-Ping fehlgeschlagen: ${result.error}`);
    if (result.status) {
      log.error(`Status: ${result.status}`);
      log.debug(`Antwort: ${JSON.stringify(result.data)}`);
    }
    return false;
  }
}

// 6. Test: Heartbeat
async function testHeartbeat() {
  log.title("Teste Heartbeat");

  const heartbeatEndpoint = `${config.apiEndpoint}/honeypot/heartbeat`;
  log.info(`Sende Heartbeat an ${heartbeatEndpoint}...`);

  const result = await makeRequest({
    url: heartbeatEndpoint,
    method: "POST",
    params: {
      api_key: config.apiKey,
    },
    data: {
      honeypot_id: config.honeypotId,
    },
  });

  if (result.success) {
    log.success(`Heartbeat erfolgreich (Status: ${result.status})`);
    log.debug(`Antwort: ${JSON.stringify(result.data)}`);
    return true;
  } else {
    log.error(`Heartbeat fehlgeschlagen: ${result.error}`);
    if (result.status) {
      log.error(`Status: ${result.status}`);
      log.debug(`Antwort: ${JSON.stringify(result.data)}`);

      if (result.status === 403) {
        log.warn("403 Forbidden - Überprüfen Sie API-Key und Honeypot-ID:");
        log.warn(`API-Key: ${config.apiKey.substring(0, 8)}...`);
        log.warn(`Honeypot-ID: ${config.honeypotId}`);
      }
    }
    return false;
  }
}

// 7. Test: API-Key-Validierung
async function testApiKeyValidation() {
  log.title("Teste API-Key-Validierung");

  // Sende eine Anfrage mit ungültigem API-Key
  const invalidKey = "invalid_api_key_for_testing";
  const heartbeatEndpoint = `${config.apiEndpoint}/honeypot/heartbeat`;

  log.info(`Sende Anfrage mit ungültigem API-Key...`);

  const result = await makeRequest({
    url: heartbeatEndpoint,
    method: "POST",
    params: {
      api_key: invalidKey,
    },
    data: {
      honeypot_id: config.honeypotId,
    },
  });

  // Bei ungültigem API-Key erwarten wir einen Fehlerstatus (401 oder 403)
  if (!result.success && (result.status === 401 || result.status === 403)) {
    log.success(
      `API-Key-Validierung funktioniert korrekt (Status: ${result.status})`
    );
    return true;
  } else if (result.success) {
    log.error(`API akzeptierte ungültigen API-Key! (Status: ${result.status})`);
    log.debug(`Antwort: ${JSON.stringify(result.data)}`);
    return false;
  } else {
    log.warn(`Unerwartetes Ergebnis bei API-Key-Test: ${result.error}`);
    log.debug(
      `Status: ${result.status}, Antwort: ${JSON.stringify(result.data || {})}`
    );
    return false;
  }
}

// Interaktiver Modus
async function promptForConfig() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const question = (query) =>
    new Promise((resolve) => rl.question(query, resolve));

  console.log(
    `${colors.bright}${colors.cyan}IPSwamp Honeypot API-Tester${colors.reset}`
  );
  console.log(`${colors.dim}Aktuelle Konfiguration:${colors.reset}`);
  console.log(`API-Endpunkt: ${config.apiEndpoint}`);
  console.log(`API-Key: ${config.apiKey.substring(0, 8)}...`);
  console.log(`Honeypot-ID: ${config.honeypotId}`);
  console.log();

  const change = await question(
    "Möchten Sie die Konfiguration ändern? (j/n): "
  );

  if (change.toLowerCase() === "j" || change.toLowerCase() === "y") {
    const apiEndpoint = await question(
      `API-Endpunkt [${config.apiEndpoint}]: `
    );
    const apiKey = await question(
      `API-Key [${config.apiKey.substring(0, 8)}...]: `
    );
    const honeypotId = await question(`Honeypot-ID [${config.honeypotId}]: `);

    if (apiEndpoint) config.apiEndpoint = apiEndpoint;
    if (apiKey) config.apiKey = apiKey;
    if (honeypotId) config.honeypotId = honeypotId;

    console.log("\nAktualisierte Konfiguration:");
    console.log(`API-Endpunkt: ${config.apiEndpoint}`);
    console.log(`API-Key: ${config.apiKey.substring(0, 8)}...`);
    console.log(`Honeypot-ID: ${config.honeypotId}`);
    console.log();
  }

  const verbose = await question("Ausführliche Ausgabe aktivieren? (j/n): ");
  config.verbose =
    verbose.toLowerCase() === "j" || verbose.toLowerCase() === "y";

  rl.close();
}

// Hauptfunktion
async function main() {
  console.log(
    `${colors.bright}${colors.cyan}IPSwamp Honeypot API-Tester${colors.reset}`
  );
  console.log(
    `${colors.dim}Testet die Verbindung zum API-Backend und hilft bei der Diagnose von Problemen${colors.reset}\n`
  );

  // Interaktiver Modus, wenn gewünscht
  if (args.interactive) {
    await promptForConfig();
  }

  log.info(`API-Endpunkt: ${config.apiEndpoint}`);
  log.info(`Honeypot-ID: ${config.honeypotId}`);
  log.info(
    `API-Key: ${config.apiKey.substring(0, 8)}...${config.apiKey.slice(-4)}`
  );

  const results = [];

  // 1. DNS-Test
  results.push({
    name: "DNS-Auflösung",
    success: await testDnsResolution(),
  });

  // 2. Ping-Test
  results.push({
    name: "Ping",
    success: await testPing(),
    optional: true,
  });

  // 3. TCP-Verbindungstest
  results.push({
    name: "TCP-Verbindung",
    success: await testTcpConnection(),
  });

  // 4. HTTP-Basis-Test
  results.push({
    name: "HTTP-Basis",
    success: await testHttpBase(),
  });

  // 5. API-Ping-Test
  results.push({
    name: "API-Ping",
    success: await testApiPing(),
  });

  // 6. Heartbeat-Test
  results.push({
    name: "Heartbeat",
    success: await testHeartbeat(),
  });

  // 7. API-Key-Validierung
  results.push({
    name: "API-Key-Validierung",
    success: await testApiKeyValidation(),
  });

  // Ergebnisse anzeigen
  log.title("Testergebnisse");

  let passedTests = 0;
  let requiredTests = 0;

  results.forEach((result) => {
    const statusText = result.success
      ? `${colors.green}BESTANDEN${colors.reset}`
      : result.optional
      ? `${colors.yellow}FEHLGESCHLAGEN (Optional)${colors.reset}`
      : `${colors.red}FEHLGESCHLAGEN${colors.reset}`;

    console.log(`${result.name}: ${statusText}`);

    if (result.success) passedTests++;
    if (!result.optional) requiredTests++;
  });

  const requiredPassedTests = results.filter(
    (r) => r.success && !r.optional
  ).length;
  const success = requiredPassedTests === requiredTests;

  console.log(
    `\nErgebnis: ${passedTests} von ${results.length} Tests bestanden`
  );
  console.log(
    `${requiredPassedTests} von ${requiredTests} erforderlichen Tests bestanden`
  );

  if (success) {
    log.success(
      "\nAlle erforderlichen Tests wurden bestanden! Die API-Verbindung funktioniert korrekt."
    );
  } else {
    log.error(
      "\nEinige Tests sind fehlgeschlagen. Bitte überprüfen Sie die obigen Ergebnisse für Details."
    );

    // Empfehlungen basierend auf fehlgeschlagenen Tests
    log.title("Empfehlungen");

    if (!results[0].success) {
      // DNS
      log.error(
        "DNS-Auflösung fehlgeschlagen. Überprüfen Sie die Konnektivität und den API-Endpunkt."
      );
      log.info("- Stellen Sie sicher, dass Sie eine Internetverbindung haben");
      log.info("- Überprüfen Sie, ob der API-Endpunkt korrekt ist");
      log.info(
        `- Versuchen Sie, den Host manuell aufzulösen: nslookup ${
          new URL(config.apiEndpoint).hostname
        }`
      );
    }

    if (!results[2].success) {
      // TCP
      log.error(
        "TCP-Verbindung fehlgeschlagen. Möglicherweise ist der API-Server nicht erreichbar oder wird durch eine Firewall blockiert."
      );
      log.info("- Überprüfen Sie, ob der Server aktiv ist");
      log.info(
        "- Stellen Sie sicher, dass keine Firewall den Zugriff blockiert"
      );
      log.info("- Testen Sie die Verbindung von einem anderen Netzwerk aus");
    }

    if (!results[3].success) {
      // HTTP
      log.error(
        "HTTP-Basis-Test fehlgeschlagen. Möglicherweise haben Sie Probleme mit der HTTP-Verbindung."
      );
      log.info("- Überprüfen Sie Ihre Internet-Verbindung");
      log.info("- Testen Sie, ob die Website im Browser erreichbar ist");
      log.info(
        "- Überprüfen Sie auf SSL/TLS-Probleme, wenn HTTPS verwendet wird"
      );
    }

    if (!results[5].success) {
      // Heartbeat
      log.error(
        "Heartbeat-Test fehlgeschlagen. Dies könnte ein Problem mit der Authentifizierung oder den API-Parametern sein."
      );
      log.info("- Überprüfen Sie Ihren API-Schlüssel auf Gültigkeit");
      log.info(
        "- Stellen Sie sicher, dass die Honeypot-ID korrekt und autorisiert ist"
      );
      log.info("- Überprüfen Sie das Format der Anfrage");

      // Curl-Befehl als Alternative anbieten
      const curlCmd = `curl -X POST "${config.apiEndpoint}/honeypot/heartbeat?api_key=${config.apiKey}" -H "Content-Type: application/json" -d '{"honeypot_id": "${config.honeypotId}"}'`;
      log.info(`- Versuchen Sie manuell: ${curlCmd}`);
    }
  }
}

// Programm starten
main().catch((error) => {
  log.error(`Unerwarteter Fehler: ${error.message}`);
  console.error(error);
});
