// API-Service für die Kommunikation mit dem Backend
const axios = require('axios');

// Heartbeat-Funktion zum Registrieren des Honeypots bei der API
async function sendHeartbeat(config) {
  try {
    const response = await axios.post(
      `${config.apiEndpoint}/honeypot/heartbeat`,
      {
        honeypot_id: config.honeypotId
      },
      {
        params: {
          api_key: config.apiKey
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Fehler beim Senden des Heartbeats:', error.message);
    throw error;
  }
}

// Funktion zum Melden von erkannten Angriffen
async function reportAttack(config, attackData) {
  try {
    const response = await axios.post(
      `${config.apiEndpoint}/report`,
      {
        ip_address: attackData.ip_address,
        attack_type: attackData.attack_type,
        description: attackData.description,
        evidence: attackData.evidence
      },
      {
        params: {
          api_key: config.apiKey
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Fehler beim Melden des Angriffs:', error.message);
    throw error;
  }
}

// Funktion zum Überprüfen, ob eine IP-Adresse bereits als verdächtig bekannt ist
async function checkIP(config, ipAddress) {
  try {
    const response = await axios.get(
      `${config.apiEndpoint}/get`,
      {
        params: {
          api_key: config.apiKey,
          ip: ipAddress
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Fehler beim Überprüfen der IP-Adresse:', error.message);
    throw error;
  }
}

module.exports = {
  sendHeartbeat,
  reportAttack,
  checkIP
};