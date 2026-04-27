import { withTimeout, withRetry } from './_helpers';

export async function fetchTorExits() {
  const url = `https://check.torproject.org/torbulkexitlist`;
  
  return withRetry(
    () => withTimeout(fetch(url), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.text();
  }).then(text => {
    return text.split('\n').filter(line => line.trim().length > 0 && !line.startsWith('#')).map(ip => ({
      ip: ip.trim(),
      source: 'TorExitNodes',
      type: 'tor_node'
    }));
  });
}
