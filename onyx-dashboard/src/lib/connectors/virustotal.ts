import { withTimeout, withRetry } from './_helpers';

export async function fetchVirusTotal() {
  const url = 'https://www.virustotal.com/api/v3/search?query=type:domain%20(engines:malicious%20OR%20engines:phishing)&limit=10';
  const apiKey = process.env.OSINT_VIRUSTOTAL_API_KEY;
  
  if (!apiKey) {
    throw new Error('Clé API VirusTotal manquante');
  }

  return withRetry(
    () => withTimeout(fetch(url, { headers: { 'x-apikey': apiKey } }), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (r.status === 429) {
      throw new Error('Rate limited');
    }
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => data.data || []);
}
