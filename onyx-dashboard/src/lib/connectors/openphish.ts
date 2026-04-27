import { withTimeout, withRetry } from './_helpers';

export async function fetchOpenPhish() {
  const url = `https://openphish.com/feed.txt`;
  
  return withRetry(
    () => withTimeout(fetch(url), 10_000),
    { retries: 3, backoff: 'exponential' }
  ).then(r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.text();
  }).then(text => {
    return text.split('\n').filter(line => line.trim().length > 0).map(url => ({
      url: url.trim(),
      source: 'OpenPhish',
      type: 'phishing'
    }));
  });
}
