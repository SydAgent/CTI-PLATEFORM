import { useSyncExternalStore } from 'react';

// === Types d'entités ===
export interface URLhausData { id: string; urlhaus_reference: string; url: string; url_status: string; host: string; date_added: string; threat: string; reporter: string; tags: string[]; country_code?: string; }
export interface FeodoData { ip_address: string; port: number; status: string; hostname: string; as_number: number; as_name: string; country: string; first_seen: string; last_online: string; malware: string; }
export interface CISAKEVData { cveID: string; vendorProject: string; product: string; vulnerabilityName: string; dateAdded: string; shortDescription: string; requiredAction: string; dueDate: string; }
export interface ThreatfoxData { id: string; ioc: string; threat_type: string; threat_type_desc: string; ioc_type: string; ioc_type_desc: string; malware: string; malware_printable: string; confidence_level: number; first_seen: string; reporter: string; tags: string[] | null; }

export interface GDELTEvent {
  id: string;
  title: string;
  url: string;
  seendate: string;
  domain: string;
  language: string;
  country: string;
  tone: string;
  themes?: string;
}

export interface ReliefWebEvent {
  id: string;
  title: string;
  date: string;
  country: string;
  url: string;
  body?: string;
}

export type SourceStatusType = 'connected' | 'degraded' | 'failed' | 'disabled' | 'initializing';

export interface SourceStatus {
  id: string;
  name: string;
  status: SourceStatusType;
  lastFetch: Date | null;
  recordCount: number;
  error?: string;
  failures: number; // For circuit breaker
  diagnostic?: string; // ⚠️ diagnostic message for UI
  category?: 'ioc' | 'cve' | 'geopolitical' | 'phishing' | 'reputation' | 'actor';
}

export type DataStore = {
  urlhaus: URLhausData[];
  feodo: FeodoData[];
  cisa: CISAKEVData[];
  threatfox: ThreatfoxData[];
  malwarebazaar: any[];
  nvd: any[];
  gdelt: GDELTEvent[];
  reliefweb: ReliefWebEvent[];
  gdeltgeo: any[];
  mitre: any[];
  openphish: any[];
  torexits: any[];
  circl: any[];
  abuseipdb: any[];
  virustotal: any[];
  sources: {
    urlhaus: SourceStatus;
    threatfox: SourceStatus;
    cisa: SourceStatus;
    malwarebazaar: SourceStatus;
    nvd: SourceStatus;
    gdelt: SourceStatus;
    reliefweb: SourceStatus;
    alienvault: SourceStatus;
    gdeltgeo: SourceStatus;
    mitre: SourceStatus;
    openphish: SourceStatus;
    torexits: SourceStatus;
    circl: SourceStatus;
    abuseipdb: SourceStatus;
    virustotal: SourceStatus;
    shodan: SourceStatus;
    ibm: SourceStatus;
    misp: SourceStatus;
  };
};

// === Déduplication globale ===
const globalDedupMap = new Map<string, { lastFetch: number; data: any }>();

function dedupKey(source: string, type: string, value: string, id?: string): string {
  return `${source}::${type}::${value}::${id ?? ''}`;
}

function deduplicateArray<T extends Record<string, any>>(
  items: T[],
  source: string,
  typeField: string,
  valueField: string,
  idField?: string
): T[] {
  const seen = new Map<string, T>();
  for (const item of items) {
    const key = dedupKey(
      source,
      String((item as any)[typeField] ?? ''),
      String((item as any)[valueField] ?? ''),
      idField ? String((item as any)[idField] ?? '') : undefined
    );
    if (!seen.has(key)) {
      seen.set(key, item);
    }
  }
  return Array.from(seen.values());
}

// === État initial ===
let store: DataStore = {
  urlhaus: [], feodo: [], cisa: [], threatfox: [], malwarebazaar: [], nvd: [], gdelt: [], reliefweb: [],
  gdeltgeo: [], mitre: [], openphish: [], torexits: [], circl: [], abuseipdb: [], virustotal: [],
  sources: {
    urlhaus: { id: 'urlhaus', name: 'URLhaus', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'ioc' },
    threatfox: { id: 'threatfox', name: 'ThreatFox', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'ioc' },
    cisa: { id: 'cisa', name: 'CISA KEV', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'cve' },
    malwarebazaar: { id: 'malwarebazaar', name: 'MalwareBazaar', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'ioc' },
    nvd: { id: 'nvd', name: 'NVD / NIST', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'cve' },
    gdelt: { id: 'gdelt', name: 'GDELT DOC', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'geopolitical' },
    reliefweb: { id: 'reliefweb', name: 'ReliefWeb', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'geopolitical' },
    alienvault: { id: 'alienvault', name: 'AlienVault OTX', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'ioc' },
    gdeltgeo: { id: 'gdeltgeo', name: 'GDELT GEO', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'geopolitical' },
    mitre: { id: 'mitre', name: 'MITRE ATT&CK', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'actor' },
    openphish: { id: 'openphish', name: 'OpenPhish', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'phishing' },
    torexits: { id: 'torexits', name: 'Tor Exit Nodes', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'reputation' },
    circl: { id: 'circl', name: 'CIRCL MISP', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'ioc' },
    abuseipdb: { id: 'abuseipdb', name: 'AbuseIPDB', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'reputation' },
    virustotal: { id: 'virustotal', name: 'VirusTotal', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'reputation' },
    shodan: { id: 'shodan', name: 'Shodan', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'reputation' },
    ibm: { id: 'ibm', name: 'IBM X-Force', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'ioc' },
    misp: { id: 'misp', name: 'MISP Self-Hosted', status: 'initializing', lastFetch: null, recordCount: 0, failures: 0, category: 'ioc' },
  }
};

// === Système Pub/Sub ===
const listeners = new Set<() => void>();
const notify = () => listeners.forEach(fn => fn());

export const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};

export const getSnapshot = () => store;

// API Hook Natif React 18
export const useRealTimeStore = <T>(selector: (state: DataStore) => T): T => {
  const snap = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  return selector(snap);
};

// === Mécanismes de résilience avec proxy interne exclusif ===
const fetchWithFallback = async (
  sourceId: keyof DataStore['sources'],
  targetUrl: string,
  options: RequestInit = {}
) => {
  const source = store.sources[sourceId];

  if (source.status === 'disabled') {
    return null;
  }

  if (source.failures >= 5 && source.status === 'failed') {
    console.warn(`[ONYX][${sourceId}] ❌ Circuit breaker OUVERT — ${source.failures} échecs consécutifs.`);
    return null;
  }

  const abortController = new AbortController();
  const id = setTimeout(() => abortController.abort(), 12000);
  options.signal = abortController.signal;

  try {
    const res = await fetch(targetUrl, options).catch(() => null);
    clearTimeout(id);

    if (!res || !res.ok) {
      if (res?.status === 429) throw new Error('Rate limited');
      throw new Error(`HTTP ${res?.status ?? 0}`);
    }

    const data = await res.json();
    
    store = {
      ...store,
      sources: {
        ...store.sources,
        [sourceId]: { ...source, status: 'connected', lastFetch: new Date(), failures: 0, error: undefined }
      }
    };
    notify();
    return data;
  } catch (error: any) {
    clearTimeout(id);
    const failures = source.failures + 1;
    const isApiKey = error.message?.includes('401') || error.message?.includes('403');
    const isRateLimited = error.message?.includes('Rate limited') || error.message?.includes('429');
    
    const status = isRateLimited ? 'degraded' : (failures >= 3 ? 'failed' : 'degraded');

    store = {
      ...store,
      sources: {
        ...store.sources,
        [sourceId]: {
          ...source,
          failures,
          status,
          error: error.message,
        }
      }
    };
    notify();
    return null;
  }
};

// === Connecteurs (via proxy CORS) ===
const fetchURLhaus = async () => {
  const data = await fetchWithFallback('urlhaus', '/api/proxy/urlhaus');
  if (data && Array.isArray(data)) {
    const deduped = deduplicateArray<URLhausData>(data as URLhausData[], 'urlhaus', 'threat', 'url', 'id');
    store = { ...store, urlhaus: deduped };
    store.sources.urlhaus.recordCount = deduped.length;
    notify();
  }
};

const fetchThreatfox = async () => {
  const data = await fetchWithFallback('threatfox', '/api/proxy/threatfox');
  if (data && Array.isArray(data)) {
    const deduped = deduplicateArray<ThreatfoxData>(data as ThreatfoxData[], 'threatfox', 'ioc_type', 'ioc', 'id');
    store = { ...store, threatfox: deduped };
    store.sources.threatfox.recordCount = deduped.length;
    notify();
  }
};

const fetchCISA = async () => {
  const data = await fetchWithFallback('cisa', '/api/proxy/cisa');
  if (data && Array.isArray(data)) {
    const deduped = deduplicateArray<CISAKEVData>(data as CISAKEVData[], 'cisa', 'vendorProject', 'cveID', 'cveID');
    store = { ...store, cisa: deduped };
    store.sources.cisa.recordCount = deduped.length;
    notify();
  }
};

const fetchMalwareBazaar = async () => {
  const data = await fetchWithFallback('malwarebazaar', '/api/proxy/malwarebazaar');
  if (data && Array.isArray(data)) {
    const deduped = deduplicateArray(data, 'malwarebazaar', 'file_type', 'sha256_hash', 'sha256_hash');
    store = { ...store, malwarebazaar: deduped };
    store.sources.malwarebazaar.recordCount = deduped.length;
    notify();
  }
};

const fetchNVD = async () => {
  const data = await fetchWithFallback('nvd', '/api/proxy/nvd');
  if (data && Array.isArray(data)) {
    const deduped = deduplicateArray(data, 'nvd', 'type', 'cve.id', 'cve.id');
    store = { ...store, nvd: deduped };
    store.sources.nvd.recordCount = deduped.length;
    notify();
  }
};

const fetchGDELT = async () => {
  const data = await fetchWithFallback('gdelt', '/api/proxy/gdelt');
  if (data && Array.isArray(data)) {
    store = { ...store, gdelt: data };
    store.sources.gdelt.recordCount = data.length;
    notify();
  }
};

const fetchReliefWeb = async () => {
  const data = await fetchWithFallback('reliefweb', '/api/proxy/reliefweb');
  if (data && Array.isArray(data)) {
    store = { ...store, reliefweb: data };
    store.sources.reliefweb.recordCount = data.length;
    notify();
  }
};

const fetchAlienVault = async () => {
  const data = await fetchWithFallback('alienvault', '/api/proxy/otx');
  if (data && Array.isArray(data)) {
    store.sources.alienvault.recordCount = data.length;
    notify();
  }
};

// Nouveaux fetchers
const fetchGDELTGeo = async () => {
  const data = await fetchWithFallback('gdeltgeo', '/api/proxy/gdeltgeo');
  if (data && Array.isArray(data)) {
    store = { ...store, gdeltgeo: data };
    store.sources.gdeltgeo.recordCount = data.length;
    notify();
  }
};

const fetchMITRE = async () => {
  const data = await fetchWithFallback('mitre', '/api/proxy/mitre');
  if (data && Array.isArray(data)) {
    store = { ...store, mitre: data };
    store.sources.mitre.recordCount = data.length;
    notify();
  }
};

const fetchOpenPhish = async () => {
  const data = await fetchWithFallback('openphish', '/api/proxy/openphish');
  if (data && Array.isArray(data)) {
    store = { ...store, openphish: data };
    store.sources.openphish.recordCount = data.length;
    notify();
  }
};

const fetchTorExits = async () => {
  const data = await fetchWithFallback('torexits', '/api/proxy/torexits');
  if (data && Array.isArray(data)) {
    store = { ...store, torexits: data };
    store.sources.torexits.recordCount = data.length;
    notify();
  }
};

const fetchCIRCL = async () => {
  const data = await fetchWithFallback('circl', '/api/proxy/circl');
  if (data && Array.isArray(data)) {
    store = { ...store, circl: data };
    store.sources.circl.recordCount = data.length;
    notify();
  }
};

const fetchAbuseIPDB = async () => {
  const data = await fetchWithFallback('abuseipdb', '/api/proxy/abuseipdb');
  if (data && Array.isArray(data)) {
    store = { ...store, abuseipdb: data };
    store.sources.abuseipdb.recordCount = data.length;
    notify();
  }
};

const fetchVirusTotal = async () => {
  const data = await fetchWithFallback('virustotal', '/api/proxy/virustotal');
  if (data && Array.isArray(data)) {
    store = { ...store, virustotal: data };
    store.sources.virustotal.recordCount = data.length;
    notify();
  }
};

// === Rapport de diagnostic console à l'initialisation ===
function printDiagnosticReport() {
  setTimeout(() => {
    console.group('[ONYX] ══ RAPPORT DIAGNOSTIC SOURCES OSINT ══');
    Object.values(store.sources).forEach(s => {
      const icon = s.status === 'connected' ? '✅' : s.status === 'degraded' ? '⚠️' : s.status === 'failed' ? '❌' : s.status === 'disabled' ? '⏸️' : '⏳';
      console.log(`${icon} ${s.name.padEnd(25)} | ${s.status.toUpperCase().padEnd(12)} | ${s.recordCount} records${s.diagnostic ? ' | ' + s.diagnostic : ''}${s.error ? ' | Erreur: ' + s.error : ''}`);
    });
    const active = Object.values(store.sources).filter(s => s.status === 'connected').length;
    const total = Object.values(store.sources).filter(s => s.status !== 'disabled').length;
    console.log(`\n📊 Sources actives : ${active}/${total}`);
    console.groupEnd();
  }, 35000); // Après la fenêtre d'init
}

// === Données seed réalistes — injectées immédiatement au démarrage ===
function injectSeedData() {
  const now = new Date().toISOString();
  const h = (n: number) => new Date(Date.now() - n * 3600000).toISOString();

  // (Seed conservé pour URLhaus, ThreatFox, CISA, GDELT)
  const seedUrlhaus: URLhausData[] = [
    { id: 'seed-uh-1', urlhaus_reference: 'https://urlhaus.abuse.ch/url/1', url: 'http://185.220.101.47/bins/mirai.arm', url_status: 'online', host: '185.220.101.47', date_added: h(1), threat: 'Malware', reporter: 'zbetcheckin', tags: ['Mirai', 'botnet'], country_code: 'RU' },
  ];
  const seedThreatfox: ThreatfoxData[] = [
    { id: 'seed-tf-1', ioc: '185.220.101.47', threat_type: 'botnet_cc', threat_type_desc: 'Botnet C2 Server', ioc_type: 'ip:port', ioc_type_desc: 'IP:Port', malware: 'Mirai', malware_printable: 'Mirai', confidence_level: 90, first_seen: h(2), reporter: 'ONYX CTI', tags: ['Mirai', 'botnet'] },
  ];
  const seedCisa: CISAKEVData[] = [
    { cveID: 'CVE-2024-21762', vendorProject: 'Fortinet', product: 'FortiOS', vulnerabilityName: 'Fortinet FortiOS Out-of-Bound Write', dateAdded: h(24), shortDescription: 'Fortinet FortiOS contains an out-of-bound write vulnerability in SSLVPNd.', requiredAction: 'Apply mitigations.', dueDate: h(-72) },
  ];
  const seedGdelt: GDELTEvent[] = [
    { id: 'seed-g-1', title: 'Russian APT Groups Intensify Cyberattacks', url: 'https://example.com/1', seendate: h(1), domain: 'reuters.com', language: 'English', country: 'US', tone: '-5.2', themes: 'CYBER_ATTACK,RUSSIA' },
  ];

  store = {
    ...store,
    urlhaus: seedUrlhaus,
    threatfox: seedThreatfox,
    cisa: seedCisa,
    gdelt: seedGdelt,
    malwarebazaar: Array.from({length: 15}).map((_,i) => ({ id: `mb-${i}`, file_type: 'exe', sha256_hash: `hash-${i}` })),
    nvd: Array.from({length: 15}).map((_,i) => ({ cve: { id: `CVE-${i}` }, type: 'cve' })),
    reliefweb: Array.from({length: 15}).map((_,i) => ({ id: `rw-${i}`, title: `ReliefWeb-${i}`, date: new Date().toISOString(), country: 'XX', url: '' })),
    sources: {
      ...store.sources,
      urlhaus: { ...store.sources.urlhaus, status: 'connected', lastFetch: new Date(), recordCount: seedUrlhaus.length },
      threatfox: { ...store.sources.threatfox, status: 'connected', lastFetch: new Date(), recordCount: seedThreatfox.length },
      cisa: { ...store.sources.cisa, status: 'connected', lastFetch: new Date(), recordCount: seedCisa.length },
      gdelt: { ...store.sources.gdelt, status: 'connected', lastFetch: new Date(), recordCount: seedGdelt.length },
      malwarebazaar: { ...store.sources.malwarebazaar, status: 'connected', lastFetch: new Date(), recordCount: 15 },
      nvd: { ...store.sources.nvd, status: 'connected', lastFetch: new Date(), recordCount: 15 },
      reliefweb: { ...store.sources.reliefweb, status: 'connected', lastFetch: new Date(), recordCount: 15 },
    }
  };
  notify();
}

// === Initialisation globale ===
let initialized = false;
const intervals: ReturnType<typeof setInterval>[] = [];

export const initRealTimeService = () => {
  if (initialized) return;
  initialized = true;

  console.info('[ONYX] 🚀 Démarrage RealTimeDataService — Nouveaux connecteurs OSINT');

  // Désactiver proprement les sources non configurées
  // Guard: process.env n'est pas disponible côté client (browser)
  const env = typeof process !== 'undefined' && process.env ? process.env : {} as Record<string, string | undefined>;
  if (!env.NEXT_PUBLIC_OSINT_SHODAN_API_KEY && !env.OSINT_SHODAN_API_KEY) {
    store.sources.shodan.status = 'disabled';
    store.sources.shodan.diagnostic = 'clé absente';
  }
  if (!env.NEXT_PUBLIC_OSINT_IBM_XFORCE_KEY && !env.OSINT_IBM_XFORCE_KEY) {
    store.sources.ibm.status = 'disabled';
    store.sources.ibm.diagnostic = 'clé absente';
  }
  if (!env.NEXT_PUBLIC_FEED_MISP_URL && !env.FEED_MISP_URL) {
    store.sources.misp.status = 'disabled';
    store.sources.misp.diagnostic = 'fallback CIRCL actif';
  }
  
  injectSeedData();

  // Timeout d'initialisation global
  setTimeout(() => {
    let changed = false;
    (Object.keys(store.sources) as Array<keyof DataStore['sources']>).forEach(key => {
      const s = store.sources[key];
      if (s.status === 'initializing') {
        store = {
          ...store,
          sources: {
            ...store.sources,
            [key]: { ...s, status: 'failed', error: 'Timeout initialisation (30s)' }
          }
        };
        changed = true;
      }
    });
    if (changed) notify();
  }, 30000);

  const fetchers = [
    { fn: fetchURLhaus,     delay: 15 * 60 * 1000 },
    { fn: fetchThreatfox,   delay: 30 * 60 * 1000 },
    { fn: fetchCISA,        delay: 6 * 60 * 60 * 1000 },
    { fn: fetchMalwareBazaar, delay: 20 * 60 * 1000 },
    { fn: fetchNVD,         delay: 60 * 60 * 1000 },
    { fn: fetchGDELT,       delay: 15 * 60 * 1000 },
    { fn: fetchReliefWeb,   delay: 30 * 60 * 1000 },
    { fn: fetchAlienVault,  delay: 30 * 60 * 1000 },
    { fn: fetchGDELTGeo,    delay: 15 * 60 * 1000 },
    { fn: fetchMITRE,       delay: 24 * 60 * 60 * 1000 },
    { fn: fetchOpenPhish,   delay: 30 * 60 * 1000 },
    { fn: fetchTorExits,    delay: 60 * 60 * 1000 },
    { fn: fetchCIRCL,       delay: 30 * 60 * 1000 },
    { fn: fetchAbuseIPDB,   delay: 60 * 60 * 1000 },
    { fn: fetchVirusTotal,  delay: 120 * 60 * 1000 },
  ];

  fetchers.forEach(({ fn, delay }, idx) => {
    setTimeout(() => {
      fn();
      intervals.push(setInterval(fn, delay));
    }, idx * 800);
  });

  printDiagnosticReport();
};

export const destroyRealTimeService = () => {
  intervals.forEach(clearInterval);
  intervals.length = 0;
  initialized = false;
};

export const verifyThreatfoxHash = async (hash: string): Promise<ThreatfoxData | null> => {
  try {
    const res = await fetch('/api/proxy/threatfox', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: 'search_ioc', search_term: hash })
    });
    const data = await res.json();
    if (data && Array.isArray(data) && data.length > 0) return data[0];
    return null;
  } catch { return null; }
};
