export async function withTimeout<T>(promise: Promise<T>, ms: number = 10000): Promise<T> {
  const timeout = new Promise<never>((_, reject) => {
    const id = setTimeout(() => {
      clearTimeout(id);
      reject(new Error(`Timeout of ${ms}ms exceeded`));
    }, ms);
  });
  return Promise.race([promise, timeout]);
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  options: { retries: number; backoff: 'exponential' | 'fixed' }
): Promise<T> {
  let attempts = 0;
  while (attempts < options.retries) {
    try {
      return await fn();
    } catch (error) {
      attempts++;
      if (attempts >= options.retries) {
        throw error;
      }
      const delay = options.backoff === 'exponential' ? Math.pow(2, attempts) * 1000 : 1000;
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw new Error('Unreachable');
}
