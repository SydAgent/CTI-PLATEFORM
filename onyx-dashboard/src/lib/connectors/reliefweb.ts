import { withTimeout, withRetry } from './_helpers';

export async function fetchReliefWeb() {
  const url = 'https://api.reliefweb.int/v1/reports?appname=onyx-cti&limit=50&profile=full&sort[]=date:desc';
  
  return withRetry(
    () => withTimeout(fetch(url), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => {
    if (!data.data) return [];
    return data.data.map((r: any) => ({
      id: r.id || String(Math.random()),
      title: r.fields?.title || 'Rapport ReliefWeb',
      date: r.fields?.date?.original || new Date().toISOString(),
      country: r.fields?.primary_country?.name || 'International',
      url: r.fields?.url_alias || r.fields?.url || '',
      body: r.fields?.body?.substring(0, 300),
    }));
  });
}
