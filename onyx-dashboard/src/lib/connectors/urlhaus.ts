import { withTimeout, withRetry } from './_helpers';

export async function fetchURLhaus() {
  const url = 'https://urlhaus-api.abuse.ch/v1/urls/recent/';
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
  
  const apiKey = process.env.URLHAUS_API_KEY;
  if (apiKey) headers['API-Auth'] = apiKey;

  return withRetry(
    () => withTimeout(fetch(url, { method: 'POST', headers, body: 'limit=100' }), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => data.urls || []);
}
