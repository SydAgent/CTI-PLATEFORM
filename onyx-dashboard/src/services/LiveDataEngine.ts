/**
 * LiveDataEngine — Moteur de données temps réel ONYX CTI v5.1
 * Architecture singleton avec pub/sub — zéro boucle infinie garantie
 * Sources : URLhaus, Feodo, CISA KEV, Threatfox, OpenPhish
 */

import { useState, useEffect, useMemo } from 'react';

export interface LiveIOC {
  id: string;
  type: 'url' | 'ip' | 'domain' | 'hash' | 'email';
  value: string;
  threat_type: string;
  country: string;
  country_code: string;
  severity: 'critique' | 'eleve' | 'moyen' | 'faible';
  source: string;
  date_added: string;
  tags: string[];
  malware_family?: string;
  actor?: string;
  latitude?: number;
  longitude?: number;
}

export interface LiveCVE {
  cve_id: string;
  product: string;
  vendor: string;
  description: string;
  date_added: string;
  due_date: string;
  severity: 'critique' | 'eleve' | 'moyen';
}

export interface LiveSignal {
  id: string;
  timestamp: string;
  type: 'nouvelle_menace' | 'ioc_detecte' | 'vulnerabilite' | 'botnet' | 'phishing';
  title: string;
  description: string;
  severity: 'critique' | 'eleve' | 'moyen' | 'faible';
  source: string;
  country_code?: string;
  actor?: string;
  ioc_count: number;
}

export interface GeoThreatPoint {
  country: string;
  country_code: string;
  latitude: number;
  longitude: number;
  ioc_count: number;
  severity: 'critique' | 'eleve' | 'moyen' | 'faible';
  threat_types: string[];
  last_seen: string;
}

export interface LiveStore {
  iocs: LiveIOC[];
  cves: LiveCVE[];
  signals: LiveSignal[];
  geoPoints: GeoThreatPoint[];
  botnetIPs: any[];
  phishingURLs: string[];
  stats: {
    total_iocs: number;
    critical_iocs: number;
    active_botnets: number;
    cves_this_week: number;
    phishing_active: number;
    last_sync: Record<string, number>;
    source_status: Record<string, 'live' | 'cache' | 'error'>;
  };
}

// Coordonnées géographiques de référence
const GEO_COORDS: Record<string, [number, number]> = {
  RU: [55.75, 37.62], CN: [39.91, 116.39], KP: [39.03, 125.75],
  IR: [35.69, 51.42], US: [38.89, -77.04], DE: [52.52, 13.40],
  FR: [48.85, 2.35], GB: [51.51, -0.13], UA: [50.45, 30.52],
  BY: [53.90, 27.57], TR: [39.93, 32.86], BR: [-15.78, -47.93],
  IN: [28.61, 77.21], NL: [52.37, 4.90], RO: [44.43, 26.10],
  NG: [9.07, 7.40], PK: [33.72, 73.04], VN: [21.02, 105.84],
  PH: [14.60, 120.98], ID: [-6.21, 106.85], ZA: [-25.75, 28.19],
  MX: [19.43, -99.13], EG: [30.06, 31.25], JP: [35.68, 139.69],
  AU: [-35.28, 149.13], CA: [45.42, -75.69], KZ: [51.18, 71.45],
  PL: [52.23, 21.01], CZ: [50.08, 14.47], HU: [47.50, 19.04]
};

// Mapping menaces par pays — données documentées
const COUNTRY_THREAT_CONTEXT: Record<string, {
  actors: string[];
  primary_threats: string[];
  severity: 'critique' | 'eleve' | 'moyen' | 'faible';
}> = {
  RU: { actors: ['APT28', 'APT29', 'Sandworm', 'LockBit'], primary_threats: ['Espionnage étatique', 'Ransomware', 'Sabotage'], severity: 'critique' },
  CN: { actors: ['Volt Typhoon', 'APT41', 'Salt Typhoon'], primary_threats: ['Espionnage industriel', 'Pré-positionnement'], severity: 'critique' },
  KP: { actors: ['Lazarus Group', 'Kimsuky', 'Andariel'], primary_threats: ['Vol crypto', 'Espionnage nucléaire'], severity: 'critique' },
  IR: { actors: ['Charming Kitten', 'MuddyWater', 'OilRig'], primary_threats: ['Espionnage dissidents', 'Sabotage'], severity: 'critique' },
  BY: { actors: ['UNC1151', 'Ghostwriter'], primary_threats: ['Désinformation', 'Opérations influence'], severity: 'eleve' },
  TR: { actors: ['Sea Turtle', 'StrongPity'], primary_threats: ['DNS hijacking', 'Espionnage'], severity: 'eleve' },
  BR: { actors: ['Prilex', 'Grandoreiro'], primary_threats: ['Fraude bancaire', 'Malware financier'], severity: 'eleve' },
  IN: { actors: ['SideWinder', 'Patchwork'], primary_threats: ['Espionnage régional'], severity: 'eleve' },
  NG: { actors: ['SilverTerrier', 'BEC Groups'], primary_threats: ['Fraude BEC', 'Phishing financier'], severity: 'eleve' }
};

// Store singleton
let store: LiveStore = {
  iocs: [], cves: [], signals: [], geoPoints: [], botnetIPs: [], phishingURLs: [],
  stats: { total_iocs: 0, critical_iocs: 0, active_botnets: 0, cves_this_week: 0, phishing_active: 0, last_sync: {}, source_status: {} }
};

const listeners = new Set<(s: LiveStore) => void>();
const notify = () => listeners.forEach(fn => fn({ ...store }));

// Utilitaires
const assignSeverity = (tags: string[], threat_type: string): LiveIOC['severity'] => {
  const critical = ['emotet', 'cobalt', 'ransomware', 'lockbit', 'blackcat', 'conti', 'cl0p'];
  const high = ['malware', 'botnet', 'backdoor', 'rat', 'stealer', 'keylogger'];
  const combined = [...tags, threat_type].map(s => s.toLowerCase());
  if (combined.some(t => critical.some(c => t.includes(c)))) return 'critique';
  if (combined.some(t => high.some(h => t.includes(h)))) return 'eleve';
  if (combined.includes('phishing')) return 'moyen';
  return 'faible';
};

const buildGeoPoints = (iocs: LiveIOC[]): GeoThreatPoint[] => {
  const grouped: Record<string, LiveIOC[]> = {};
  iocs.forEach(ioc => {
    if (!ioc.country_code) return;
    if (!grouped[ioc.country_code]) grouped[ioc.country_code] = [];
    grouped[ioc.country_code].push(ioc);
  });
  return Object.entries(grouped).map(([code, items]) => {
    const coords = GEO_COORDS[code] || [0, 0];
    const hasCritical = items.some(i => i.severity === 'critique');
    const hasHigh = items.some(i => i.severity === 'eleve');
    return {
      country: items[0]?.country || code,
      country_code: code,
      latitude: coords[0],
      longitude: coords[1],
      ioc_count: items.length,
      severity: (hasCritical ? 'critique' : hasHigh ? 'eleve' : 'moyen') as 'critique' | 'eleve' | 'moyen' | 'faible',
      threat_types: Array.from(new Set(items.map(i => i.threat_type))).slice(0, 3),
      last_seen: items[0]?.date_added || new Date().toISOString()
    };
  }).filter(p => p.latitude !== 0);
};

const generateSignal = (ioc: LiveIOC): LiveSignal => ({
  id: `sig-${ioc.id}`,
  timestamp: ioc.date_added || new Date().toISOString(),
  type: ioc.type === 'ip' ? 'botnet' : ioc.threat_type?.includes('phish') ? 'phishing' : 'ioc_detecte',
  title: `${ioc.threat_type || 'Menace'} détecté — ${ioc.country || 'Origine inconnue'}`,
  description: `IOC de type ${ioc.type} détecté : ${ioc.value.substring(0, 60)}${ioc.value.length > 60 ? '...' : ''}`,
  severity: ioc.severity,
  source: ioc.source,
  country_code: ioc.country_code,
  ioc_count: 1
});

// Fetchers
const fetchURLhaus = async () => {
  try {
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'limit=100'
    });
    const data = await res.json();
    const urls: LiveIOC[] = (data.urls || []).map((u: any) => ({
      id: u.id || Math.random().toString(36).slice(2),
      type: 'url' as const,
      value: u.url || '',
      threat_type: u.threat || 'malware',
      country: u.country || 'Inconnu',
      country_code: u.country_code || '',
      severity: assignSeverity(u.tags || [], u.threat || ''),
      source: 'Abuse.ch URLhaus',
      date_added: u.date_added || new Date().toISOString(),
      tags: u.tags || [],
      malware_family: u.tags?.[0] || undefined,
      latitude: u.country_code ? GEO_COORDS[u.country_code]?.[0] : undefined,
      longitude: u.country_code ? GEO_COORDS[u.country_code]?.[1] : undefined
    }));
    store.iocs = [...urls, ...store.iocs.filter(i => i.source !== 'Abuse.ch URLhaus')].slice(0, 500);
    store.geoPoints = buildGeoPoints(store.iocs);
    store.signals = store.iocs.slice(0, 30).map(generateSignal);
    store.stats.source_status.urlhaus = 'live';
    store.stats.last_sync.urlhaus = Date.now();
    store.stats.total_iocs = store.iocs.length;
    store.stats.critical_iocs = store.iocs.filter(i => i.severity === 'critique').length;
  } catch {
    store.stats.source_status.urlhaus = 'cache';
    // Fallback données de référence
    if (store.iocs.length === 0) store.iocs = FALLBACK_IOCS;
  }
  notify();
};

const fetchFeodo = async () => {
  try {
    const res = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json');
    const data = await res.json();
    store.botnetIPs = data || [];
    const feodoIOCs: LiveIOC[] = (data || []).slice(0, 50).map((entry: any) => ({
      id: `feodo-${entry.ip_address}`,
      type: 'ip' as const,
      value: entry.ip_address,
      threat_type: `Botnet C2 — ${entry.malware}`,
      country: entry.country || 'Inconnu',
      country_code: entry.country_code || '',
      severity: 'critique' as const,
      source: 'Abuse.ch Feodo Tracker',
      date_added: entry.first_seen || new Date().toISOString(),
      tags: ['botnet', 'c2', entry.malware?.toLowerCase()].filter(Boolean),
      malware_family: entry.malware,
      latitude: entry.country_code ? GEO_COORDS[entry.country_code]?.[0] : undefined,
      longitude: entry.country_code ? GEO_COORDS[entry.country_code]?.[1] : undefined
    }));
    store.iocs = [...store.iocs.filter(i => i.source !== 'Abuse.ch Feodo Tracker'), ...feodoIOCs];
    store.geoPoints = buildGeoPoints(store.iocs);
    store.stats.active_botnets = store.botnetIPs.length;
    store.stats.source_status.feodo = 'live';
    store.stats.last_sync.feodo = Date.now();
  } catch {
    store.stats.source_status.feodo = 'cache';
  }
  notify();
};

const fetchCISA = async () => {
  try {
    const res = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    );
    const data = await res.json();
    const oneWeekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    store.cves = (data.vulnerabilities || [])
      .map((v: any) => ({
        cve_id: v.cveID,
        product: v.product,
        vendor: v.vendorProject,
        description: v.shortDescription,
        date_added: v.dateAdded,
        due_date: v.dueDate,
        severity: 'critique' as const
      }))
      .sort((a: any, b: any) => new Date(b.date_added).getTime() - new Date(a.date_added).getTime());
    store.stats.cves_this_week = store.cves.filter(
      c => new Date(c.date_added).getTime() > oneWeekAgo
    ).length;
    store.stats.source_status.cisa = 'live';
    store.stats.last_sync.cisa = Date.now();
  } catch {
    store.stats.source_status.cisa = 'cache';
    if (store.cves.length === 0) store.cves = FALLBACK_CVES;
  }
  notify();
};

const fetchThreatfox = async () => {
  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_iocs', days: 1 })
    });
    const data = await res.json();
    const tfIOCs: LiveIOC[] = (data.data || []).slice(0, 100).map((entry: any) => ({
      id: `tf-${entry.id}`,
      type: (entry.ioc_type === 'url' ? 'url' : entry.ioc_type === 'ip:port' ? 'ip' : 'domain') as LiveIOC['type'],
      value: entry.ioc,
      threat_type: entry.threat_type || 'malware',
      country: '',
      country_code: '',
      severity: assignSeverity([entry.malware_alias || ''], entry.threat_type || ''),
      source: 'Abuse.ch Threatfox',
      date_added: entry.first_seen || new Date().toISOString(),
      tags: entry.tags || [],
      malware_family: entry.malware,
      actor: entry.reporter
    }));
    store.iocs = [...store.iocs.filter(i => i.source !== 'Abuse.ch Threatfox'), ...tfIOCs];
    store.stats.source_status.threatfox = 'live';
    store.stats.last_sync.threatfox = Date.now();
  } catch {
    store.stats.source_status.threatfox = 'cache';
  }
  notify();
};

// Fallbacks garantis — données documentées récentes
const FALLBACK_IOCS: LiveIOC[] = [
  { id: 'fb-001', type: 'ip', value: '185.220.101.47', threat_type: 'Botnet C2 — Emotet', country: 'Allemagne', country_code: 'DE', severity: 'critique', source: 'Cache ONYX CTI', date_added: new Date().toISOString(), tags: ['emotet', 'botnet', 'c2'], malware_family: 'Emotet', latitude: 52.52, longitude: 13.40 },
  { id: 'fb-002', type: 'url', value: 'http://update-service.ru/payload.exe', threat_type: 'Malware distribution', country: 'Russie', country_code: 'RU', severity: 'critique', source: 'Cache ONYX CTI', date_added: new Date().toISOString(), tags: ['malware', 'dropper'], latitude: 55.75, longitude: 37.62 },
  { id: 'fb-003', type: 'domain', value: 'avsvmcloud.com', threat_type: 'Backdoor C2 — SUNBURST', country: 'États-Unis', country_code: 'US', severity: 'critique', source: 'Cache ONYX CTI — APT29', date_added: new Date().toISOString(), tags: ['apt29', 'sunburst', 'c2'], malware_family: 'SUNBURST', actor: 'APT29', latitude: 38.89, longitude: -77.04 },
  { id: 'fb-004', type: 'ip', value: '194.165.16.98', threat_type: 'Phishing infrastructure', country: 'Iran', country_code: 'IR', severity: 'eleve', source: 'Cache ONYX CTI', date_added: new Date().toISOString(), tags: ['phishing', 'apt35'], actor: 'Charming Kitten', latitude: 35.69, longitude: 51.42 },
  { id: 'fb-005', type: 'hash', value: '019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134', threat_type: 'Backdoor — SUNBURST', country: 'Russie', country_code: 'RU', severity: 'critique', source: 'Cache ONYX CTI — CISA', date_added: new Date().toISOString(), tags: ['sunburst', 'apt29', 'solarwinds'], actor: 'APT29', latitude: 55.75, longitude: 37.62 }
];

const FALLBACK_CVES: LiveCVE[] = [
  { cve_id: 'CVE-2024-21887', product: 'Ivanti Connect Secure', vendor: 'Ivanti', description: 'Injection de commande dans les appliances web Ivanti permettant une exécution de code à distance', date_added: '2024-01-10', due_date: '2024-01-31', severity: 'critique' },
  { cve_id: 'CVE-2024-3400', product: 'PAN-OS', vendor: 'Palo Alto Networks', description: 'Injection de commande OS dans la fonctionnalité GlobalProtect de PAN-OS', date_added: '2024-04-12', due_date: '2024-04-19', severity: 'critique' },
  { cve_id: 'CVE-2023-46805', product: 'Ivanti Policy Secure', vendor: 'Ivanti', description: 'Contournement d\'authentification dans les passerelles Ivanti permettant un accès non autorisé', date_added: '2024-01-10', due_date: '2024-01-31', severity: 'critique' }
];

// Initialisation et gestion du cycle de vie
let initialized = false;
const activeIntervals: ReturnType<typeof setInterval>[] = [];

export const initLiveDataEngine = (): void => {
  if (initialized) return;
  initialized = true;

  // Chargement initial séquentiel pour éviter la surcharge réseau
  fetchURLhaus();
  setTimeout(fetchFeodo, 2000);
  setTimeout(fetchCISA, 4000);
  setTimeout(fetchThreatfox, 6000);

  // Cycles de rafraîchissement
  activeIntervals.push(setInterval(fetchURLhaus, 15 * 60 * 1000));
  activeIntervals.push(setInterval(fetchFeodo, 30 * 60 * 1000));
  activeIntervals.push(setInterval(fetchCISA, 6 * 60 * 60 * 1000));
  activeIntervals.push(setInterval(fetchThreatfox, 30 * 60 * 1000));
};

export const destroyLiveDataEngine = (): void => {
  activeIntervals.forEach(clearInterval);
  activeIntervals.length = 0;
  initialized = false;
};

// Hook React — consommation sans boucle infinie
export const useLiveData = (): LiveStore => {
  const [data, setData] = useState<LiveStore>({ ...store });
  useEffect(() => {
    setData({ ...store });
    listeners.add(setData);
    return () => { listeners.delete(setData); };
  }, []); // tableau vide — abonnement unique au montage
  return data;
};

// Sélecteurs optimisés — évitent les re-rendus inutiles
export const useLiveIOCs = () => {
  const store = useLiveData();
  return useMemo(() => store.iocs, [store.iocs.length, store.stats.last_sync.urlhaus]);
};

export const useLiveSignals = () => {
  const store = useLiveData();
  return useMemo(() => store.signals, [store.signals.length]);
};

export const useGeoPoints = () => {
  const store = useLiveData();
  return useMemo(() => store.geoPoints, [store.geoPoints.length]);
};

export const useLiveCVEs = () => {
  const store = useLiveData();
  return useMemo(() => store.cves, [store.cves.length]);
};

export const verifyThreatfoxHash = async (hash: string): Promise<any | null> => {
  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: hash })
    });
    const data = await res.json();
    if (data && data.query_status === 'ok' && data.data && data.data.length > 0) {
      return data.data[0];
    }
    return null;
  } catch (e) {
    return null;
  }
};
