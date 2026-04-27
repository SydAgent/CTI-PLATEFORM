import { withTimeout, withRetry } from './_helpers';

const MANIFEST_URL = 'https://www.circl.lu/doc/misp/feed-osint/manifest.json';

export async function fetchCIRCLFeed(maxEvents = 20) {
  return withRetry(async () => {
    const manifestRes = await withTimeout(fetch(MANIFEST_URL), 10_000);
    if (!manifestRes.ok) throw new Error(`CIRCL manifest fetch failed: ${manifestRes.status}`);
    const manifest = await manifestRes.json();

    const entries = Object.entries(manifest)
      .map(([uuid, meta]: [string, any]) => ({ uuid, ...meta }))
      .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
      .slice(0, maxEvents);

    const events = await Promise.allSettled(
      entries.map(async (entry) => {
        const r = await withTimeout(fetch(`https://www.circl.lu/doc/misp/feed-osint/${entry.uuid}.json`), 10_000);
        if (!r.ok) throw new Error(`CIRCL event ${entry.uuid} fetch failed`);
        return r.json();
      })
    );

    return events
      .filter((r): r is PromiseFulfilledResult<any> => r.status === 'fulfilled')
      .map(r => r.value.Event);
  }, { retries: 3, backoff: 'exponential' });
}
