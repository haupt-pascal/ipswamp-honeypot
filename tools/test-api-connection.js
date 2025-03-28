/**
 * Test connection to API
 *
 * Simple utility to test connectivity to the API server from the Docker container.
 * This script sends a request to the specified API endpoint and logs the response.
 *
 * Usage:
 *   node tools/test-api-connection.js [url]
 */

const http = require("http");
const https = require("https");

// Default URL or from command line argument
const url = process.argv[2] || "http://host.docker.internal:3001/api/ping";

console.log(`Testing connection to: ${url}`);

// Parse the URL to determine the protocol (http or https)
const urlObj = new URL(url);
const protocol = urlObj.protocol === "https:" ? https : http;

// Send a GET request to the specified URL
const req = protocol.get(
  url,
  {
    timeout: 5000, // Set timeout for the request
    headers: {
      "User-Agent": "IPSwamp-Test/1.0", // Custom user-agent header
    },
  },
  (res) => {
    // Log the response status code and headers
    console.log(`STATUS: ${res.statusCode}`);
    console.log(`HEADERS: ${JSON.stringify(res.headers)}`);

    let data = "";
    // Accumulate response data chunks
    res.on("data", (chunk) => {
      data += chunk;
    });

    // Handle the end of the response
    res.on("end", () => {
      console.log("RESPONSE BODY:");
      try {
        // Attempt to parse the response body as JSON
        const parsed = JSON.parse(data);
        console.log(JSON.stringify(parsed, null, 2)); // Pretty-print JSON
      } catch (e) {
        // If parsing fails, log the raw response body
        console.log(data);
      }
    });
  }
);

// Handle request errors
req.on("error", (e) => {
  console.error(`ERROR: ${e.message}`);
  if (e.code) {
    console.error(`ERROR CODE: ${e.code}`);
  }
});

// End the request
req.end();
