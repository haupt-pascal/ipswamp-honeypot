/**
 * Test connection to API
 *
 * Simple utility to test connectivity to the API server from the Docker container
 *
 * Usage:
 *   node tools/test-api-connection.js [url]
 */

const http = require("http");
const https = require("https");

// Default URL or from command line
const url = process.argv[2] || "http://host.docker.internal:3001/api/ping";

console.log(`Testing connection to: ${url}`);

// Parse the URL
const urlObj = new URL(url);
const protocol = urlObj.protocol === "https:" ? https : http;

const req = protocol.get(
  url,
  {
    timeout: 5000,
    headers: {
      "User-Agent": "IPSwamp-Test/1.0",
    },
  },
  (res) => {
    console.log(`STATUS: ${res.statusCode}`);
    console.log(`HEADERS: ${JSON.stringify(res.headers)}`);

    let data = "";
    res.on("data", (chunk) => {
      data += chunk;
    });

    res.on("end", () => {
      console.log("RESPONSE BODY:");
      try {
        const parsed = JSON.parse(data);
        console.log(JSON.stringify(parsed, null, 2));
      } catch (e) {
        console.log(data);
      }
    });
  }
);

req.on("error", (e) => {
  console.error(`ERROR: ${e.message}`);
  if (e.code) {
    console.error(`ERROR CODE: ${e.code}`);
  }
});

req.end();
