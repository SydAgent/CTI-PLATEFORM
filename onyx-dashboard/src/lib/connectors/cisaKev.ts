import { withTimeout, withRetry } from './_helpers';

export async function fetchCISAKEV() {
  return withRetry(
    () => withTimeout(
      fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
      10_000
    ),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => data.vulnerabilities || []);
}
