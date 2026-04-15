import DOMPurify from 'dompurify';

/**
 * Enterprise-grade XSS Sanitizer for Dark Web & OSINT Intelligence.
 * Uses DOMPurify to strip malicious payloads from raw text feeds.
 */
export const sanitizePayload = <T>(payload: T): T => {
  if (typeof payload === 'string') {
    return DOMPurify.sanitize(payload) as unknown as T;
  }
  
  if (Array.isArray(payload)) {
    return payload.map(item => sanitizePayload(item)) as unknown as T;
  }
  
  if (typeof payload === 'object' && payload !== null) {
    const sanitizedObj: any = {};
    for (const [key, value] of Object.entries(payload)) {
      sanitizedObj[sanitizePayload(key)] = sanitizePayload(value);
    }
    return sanitizedObj as T;
  }
  
  return payload;
};
