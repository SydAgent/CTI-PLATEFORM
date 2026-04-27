import { withTimeout, withRetry } from './_helpers';

export async function fetchGDELTGeo() {
  const queries = [
    'cyberattack OR ransomware OR hacking',
    'conflict OR military OR war',
    'protest OR demonstration OR riot',
    'humanitarian OR crisis OR disaster',
    'sanctions OR diplomacy OR treaty',
  ];
  const query = encodeURIComponent(queries.join(' OR '));
  const url = `https://api.gdeltproject.org/api/v2/geo/geo?query=${query}&format=GeoJSON&mode=PointData&timespan=24h`;
  
  return withRetry(
    () => withTimeout(fetch(url), 15_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).then(data => {
    const features = data.features || [];
    return features.map((f: any) => ({
      type: 'Feature',
      geometry: f.geometry,
      properties: {
        name: f.properties?.name || '',
        url: f.properties?.url || f.properties?.shareimage || '',
        tone: f.properties?.tone || f.properties?.urltone || 0,
        domain: f.properties?.domain || f.properties?.domainis || '',
        seendate: f.properties?.seendate || f.properties?.date || new Date().toISOString(),
        language: f.properties?.language || f.properties?.sourcelang || 'en',
        country: f.properties?.country || f.properties?.mobilegeo || '',
        html5: f.properties?.html5 || '',
        themes: f.properties?.themes || '',
      }
    }));
  });
}
