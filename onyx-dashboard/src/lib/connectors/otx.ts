import { withTimeout, withRetry } from './_helpers';

export async function fetchOTX() {
  const url = 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50';
  const apiKey = process.env.OTX_API_KEY || process.env.OSINT_ALIENVAULT_OTX_KEY || process.env.NEXT_PUBLIC_OTX_KEY;
  
  if (!apiKey) {
    throw new Error('Clé API OTX manquante');
  }

  return withRetry(
    () => withTimeout(fetch(url, { headers: { 'X-OTX-API-KEY': apiKey } }), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => data.results || []);
}
