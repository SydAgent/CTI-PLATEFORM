import { withTimeout, withRetry } from './_helpers';

export async function fetchThreatfox() {
  const url = 'https://threatfox-api.abuse.ch/api/v1/';
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  
  const apiKey = process.env.URLHAUS_API_KEY;
  if (apiKey) headers['API-Auth'] = apiKey;

  return withRetry(
    () => withTimeout(fetch(url, { method: 'POST', headers, body: JSON.stringify({ query: 'get_iocs', days: 1 }) }), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => data.data || []);
}
