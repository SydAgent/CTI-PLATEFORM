import { withTimeout, withRetry } from './_helpers';

export async function fetchMITRE() {
  const url = `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`;
  
  return withRetry(
    () => withTimeout(fetch(url), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => {
    if (!data.objects) return [];
    return data.objects.filter((o: any) => o.type === 'intrusion-set' || o.type === 'malware');
  });
}
