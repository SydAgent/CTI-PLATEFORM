export const safeString = (val: unknown): string => {
  if (val === null || val === undefined) return '';
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'boolean') return String(val);
  if (Array.isArray(val)) return val.map(safeString).filter(Boolean).join(', ');
  if (typeof val === 'object') {
    const o = val as Record<string, unknown>;
    const candidate = o.name || o.label || o.title || o.value || o.id || o.text;
    if (candidate) return safeString(candidate);
    return JSON.stringify(val);
  }
  return String(val);
};

export const safeActorName = (actor: unknown): string => {
  if (typeof actor === 'string') return actor;
  if (typeof actor === 'object' && actor !== null) {
    const a = actor as Record<string, unknown>;
    return safeString(a.name || a.actor_name || a.threat_actor || a.label || actor);
  }
  return safeString(actor);
};
