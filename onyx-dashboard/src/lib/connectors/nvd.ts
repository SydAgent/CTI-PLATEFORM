import { withTimeout, withRetry } from './_helpers';

export async function fetchNVD() {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20`;
  
  return withRetry(
    () => withTimeout(fetch(url), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => data.vulnerabilities || []);
}
