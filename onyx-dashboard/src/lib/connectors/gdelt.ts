import { withTimeout, withRetry } from './_helpers';

export async function fetchGDELT() {
  const query = encodeURIComponent('(cyberattack OR "critical infrastructure" OR ransomware OR APT OR espionage OR geopolitical) sourcelang:english');
  const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=${query}&mode=artlist&maxrecords=50&format=json&timespan=1d`;
  
  return withRetry(
    () => withTimeout(fetch(url), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => {
    if (!data.articles) return [];
    return data.articles.map((a: any, i: number) => ({
      id: `gdelt-${i}-${Date.now()}`,
      title: a.title || 'Événement géopolitique',
      url: a.url || '',
      seendate: a.seendate || new Date().toISOString(),
      domain: a.domain || '',
      language: a.language || 'en',
      country: a.sourcecountry || a.country || 'XX',
      tone: a.tone || '0',
      themes: a.themes || '',
    }));
  });
}
