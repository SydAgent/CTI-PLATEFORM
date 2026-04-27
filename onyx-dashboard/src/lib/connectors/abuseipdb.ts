import { withTimeout, withRetry } from './_helpers';

export async function fetchAbuseIPDB() {
  const url = 'https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90';
  const apiKey = process.env.OSINT_ABUSEIPDB_API_KEY;
  
  if (!apiKey) {
    throw new Error('Clé API AbuseIPDB manquante');
  }

  return withRetry(
    () => withTimeout(fetch(url, { headers: { 'Accept': 'application/json', 'Key': apiKey } }), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => data.data || []);
}
