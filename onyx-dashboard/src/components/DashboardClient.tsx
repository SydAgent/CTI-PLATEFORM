'use client';

import { useEffect, useState, useCallback } from 'react';
import dynamic from 'next/dynamic';
import jsPDF from 'jspdf';
import Papa from 'papaparse';
import AttackMatrix from '@/components/AttackMatrix';
import SciBERTEnginePanel from '@/components/SciBERTEnginePanel';
import SIEMRuleConverter from '@/components/SIEMRuleConverter';
import NLPAnalyzer from '@/components/NLPAnalyzer';
import AgenticCopilot from '@/components/AgenticCopilot';
import IntelligenceBrief from '@/components/IntelligenceBrief';

// ─── CSR-ONLY WebGL components ──────────────────────────────────────────────
// These dynamic() calls are inside a Client Component, but the trick is page.tsx
// is a SERVER component that dynamically imports THIS file with ssr:false.
// This means Next.js will NEVER evaluate any import in this tree on the server.
const ThreatMap3D = dynamic(() => import('@/components/ThreatMap3D'), {
  ssr: false,
  loading: () => (
    <div style={{ width:'100%', height:'400px', background:'#050a0f', borderRadius:'12px', display:'flex', alignItems:'center', justifyContent:'center', border:'1px solid rgba(0,238,255,0.15)' }}>
      <div style={{ color:'#00eeff', fontFamily:'monospace', fontSize:'11px', opacity:0.4, letterSpacing:'0.1em' }}>⬡ INITIALIZING GEOPOLITICAL THREAT MATRIX...</div>
    </div>
  ),
});
const ThreatGraph = dynamic(() => import('@/components/ThreatGraph'), {
  ssr: false,
  loading: () => (
    <div className="onyx-card" style={{ height:'600px', display:'flex', alignItems:'center', justifyContent:'center' }}>
      <div style={{ color:'var(--text-tertiary)', fontFamily:'var(--font-mono)', fontSize:'var(--font-size-sm)' }}>◎ Loading WebGL Graph Engine...</div>
    </div>
  ),
});

/* ============================================================================
   Types
   ============================================================================ */
interface DashboardStats {
  iocs: { total_iocs?: { value: number }; by_type?: { buckets: Array<{ key: string; doc_count: number }> }; by_severity?: { buckets: Array<{ key: string; doc_count: number }> }; timeline_24h?: { buckets: Array<{ key_as_string: string; doc_count: number }> }; avg_confidence?: { value: number } };
  threats: { total_threats?: { value: number }; by_type?: { buckets: Array<{ key: string; doc_count: number }> } };
  stix: { types: Record<string, number>; total: number };
  crawlers: Array<{ crawler_id: string; status: string; last_run?: string }>;
}

interface IOC { type: string; value: string; source: string; confidence: number; }

interface SSEEvent {
  type: string;
  data: Record<string, unknown>;
  timestamp: string;
}

/* ============================================================================
   API
   ============================================================================ */
const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

async function apiFetch<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(`${API}${path}`, { cache: 'no-store' });
    if (!res.ok) return null;
    return res.json();
  } catch { return null; }
}

/* ============================================================================
   Hooks — Resilient SSE with grace period & exponential backoff
   ============================================================================ */
function useSSE(url: string) {
  const [events, setEvents]       = useState<SSEEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [liveIocCount, setLiveIocCount] = useState(0);

  useEffect(() => {
    let es: EventSource | null = null;
    let reconnectDelay = 1000;            // starts at 1s, doubles up to 8s
    let reconnectTimer: ReturnType<typeof setTimeout>;
    let graceTimer:     ReturnType<typeof setTimeout>;  // 8s grace before OFFLINE

    const resetGraceTimer = () => {
      clearTimeout(graceTimer);
      setConnected(true);
      // Only declare OFFLINE if we get NO heartbeat for 8 full seconds
      graceTimer = setTimeout(() => setConnected(false), 8000);
    };

    const connect = () => {
      try { es?.close(); } catch {}
      try {
        es = new EventSource(url);

        es.onopen = () => { resetGraceTimer(); reconnectDelay = 1000; };

        const handleEvent = (e: MessageEvent) => {
          resetGraceTimer();
          try {
            const data = JSON.parse(e.data);
            const evType = (e as any).type || 'message';
            // Increment live IOC counter on every real detection
            if (evType === 'ioc_detected') {
              setLiveIocCount(c => c + 1);
            }
            setEvents(prev => [
              { type: evType, data, timestamp: new Date().toISOString() },
              ...prev.slice(0, 149)   // keep last 150 events
            ]);
          } catch {}
        };

        es.addEventListener('heartbeat',    handleEvent as EventListener);
        es.addEventListener('ioc_detected', handleEvent as EventListener);
        es.addEventListener('nlp_extraction', handleEvent as EventListener);
        es.onmessage = handleEvent;

        es.onerror = () => {
          // Don't reset connected — let the grace timer handle it
          es?.close();
          clearTimeout(reconnectTimer);
          reconnectTimer = setTimeout(() => {
            reconnectDelay = Math.min(reconnectDelay * 2, 8000);
            connect();
          }, reconnectDelay);
        };
      } catch {
        reconnectTimer = setTimeout(connect, 3000);
      }
    };

    connect();
    return () => {
      clearTimeout(reconnectTimer);
      clearTimeout(graceTimer);
      es?.close();
    };
  }, [url]);

  return { events, connected, liveIocCount };
}

/* ============================================================================
   Shared UI Primitives
   ============================================================================ */
function Logo() {
  return (
    <div className="onyx-logo">
      <div className="logo-mark">◆</div>
      <div>
        <div className="logo-text">ONYX</div>
        <div className="logo-version">CTI v3.0 GENESIS</div>
      </div>
    </div>
  );
}

const NAV_ITEMS = [
  { id: 'overview',  icon: '◈', label: 'Overview'      },
  { id: 'ailab',     icon: '⟁', label: 'AI Lab'        },
  { id: 'iocs',      icon: '⬡', label: 'IOC Explorer'  },
  { id: 'threats',   icon: '☠', label: 'Threat Actors' },
  { id: 'graph',     icon: '◎', label: 'Threat Graph'  },
  { id: 'crawlers',  icon: '🕸', label: 'Crawlers'      },
  { id: 'reports',   icon: '📋', label: 'Reports'       },
  { id: 'attack',    icon: '⚔', label: 'ATT&CK Matrix' },
];

function Sidebar({ activeTab, onTabChange }: { activeTab: string; onTabChange: (t: string) => void }) {
  return (
    <aside className="onyx-sidebar">
      <Logo />
      <nav style={{ flex: 1 }}>
        {NAV_ITEMS.map(item => (
          <div key={item.id} className={`nav-item ${activeTab === item.id ? 'active' : ''}`} onClick={() => onTabChange(item.id)}>
            <span className="nav-icon">{item.icon}</span>
            <span>{item.label}</span>
          </div>
        ))}
      </nav>
      <div style={{ padding: '0 var(--space-lg)', marginTop: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)', fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)' }}>
          <span className="pulse-live" />
          <span>System Online</span>
        </div>
      </div>
    </aside>
  );
}

function Header({ connected }: { connected: boolean }) {
  const [time, setTime] = useState('');
  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString('en-US', { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <header className="onyx-header">
      <div className="search-bar">
        <span style={{ color: 'var(--text-tertiary)' }}>⌕</span>
        <input type="text" placeholder="Search IOCs, threats, TTPs..." />
        <span className="shortcut">⌘K</span>
      </div>
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 'var(--space-md)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-xs)', fontSize: 'var(--font-size-xs)', color: connected ? 'var(--onyx-green)' : 'var(--onyx-red)', fontFamily: 'var(--font-mono)' }}>
          <span className="pulse-live" style={{ background: connected ? 'var(--onyx-green)' : 'var(--onyx-red)' }} />
          {connected ? '● LIVE' : '○ OFFLINE'}
        </div>
        <span suppressHydrationWarning style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>
          {time} UTC
        </span>
      </div>
    </header>
  );
}

function StatCard({ label, value, trend, icon, color }: { label: string; value: string | number; trend?: string; icon: string; color?: string }) {
  return (
    <div className="onyx-card stat-widget animate-in" style={{ borderLeft: color ? `3px solid ${color}` : undefined }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="stat-label">{label}</div>
          <div className="stat-value">{typeof value === 'number' ? value.toLocaleString() : value}</div>
        </div>
        <span style={{ fontSize: '1.8rem', opacity: 0.4 }}>{icon}</span>
      </div>
      {trend && <div className={`stat-trend ${trend.startsWith('+') ? 'up' : 'down'}`}>
        <span>{trend.startsWith('+') ? '▲' : '▼'}</span> {trend}
      </div>}
    </div>
  );
}

function IOCTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    ipv4: 'var(--onyx-cyan)', domain: 'var(--onyx-magenta)', url: 'var(--onyx-amber)',
    sha256: 'var(--onyx-green)', md5: 'var(--onyx-green)', email: 'var(--severity-high)', cve: 'var(--onyx-red)',
  };
  return (
    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-xs)', padding: '2px 8px', borderRadius: 'var(--radius-full)', background: `${colors[type] || 'var(--text-tertiary)'}22`, color: colors[type] || 'var(--text-tertiary)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
      {type}
    </span>
  );
}

function SeverityBar({ severity, count, total }: { severity: string; count: number; total: number }) {
  const colors: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6' };
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#6b7280', width: 55, textTransform: 'uppercase' }}>{severity}</span>
      <div style={{ flex: 1, height: 6, background: '#1f2937', borderRadius: 99, overflow: 'hidden' }}>
        <div style={{ width: `${(count / total) * 100}%`, height: '100%', background: colors[severity] || '#6b7280', borderRadius: 99, transition: 'width 1s ease-out' }} />
      </div>
      <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#9ca3af', width: 32, textAlign: 'right' }}>{count}</span>
    </div>
  );
}

function LiveFeed({ events }: { events: SSEEvent[] }) {
  return (
    <div className="onyx-card animate-in" style={{ height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-md)' }}>
        <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
          <span className="pulse-live" /> Live Event Feed
        </h3>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)' }}>{events.length} events</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)', maxHeight: 320, overflowY: 'auto' }}>
        {events.length === 0 && <div style={{ textAlign: 'center', padding: 'var(--space-xl)', color: 'var(--text-tertiary)', fontSize: 'var(--font-size-sm)' }}>Connecting to live stream...</div>}
        {events.map((ev, i) => (
          <div key={i} className="animate-in" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-md)', padding: '6px 12px', background: 'var(--onyx-bg-tertiary)', borderRadius: 'var(--radius-sm)', borderLeft: `3px solid var(--onyx-cyan)` }}>
            <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-tertiary)', whiteSpace: 'nowrap' }}>{new Date(ev.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
            <span className="ioc-value" style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{String(ev.data?.value || ev.type || 'event')}</span>
            <IOCTypeBadge type={String(ev.data?.type || 'info')} />
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============================================================================
   IOC Explorer
   ============================================================================ */
const FALLBACK_IOCS: IOC[] = [
  { type: 'ipv4', value: '185.220.101.45', source: 'MISP Widespread Bad IPs', confidence: 98.5 },
  { type: 'ipv4', value: '91.108.56.181',  source: 'MISP Widespread Bad IPs', confidence: 97.2 },
  { type: 'ipv4', value: '5.188.86.172',   source: 'MISP Widespread Bad IPs', confidence: 96.8 },
  { type: 'ipv4', value: '194.165.16.78',  source: 'MISP Widespread Bad IPs', confidence: 99.1 },
  { type: 'ipv4', value: '45.142.212.100', source: 'MISP Widespread Bad IPs', confidence: 95.3 },
  { type: 'ipv4', value: '77.83.36.18',    source: 'MISP Widespread Bad IPs', confidence: 98.0 },
  { type: 'domain', value: 'onion-router-c2.tk',      source: 'SpiderFoot OSINT', confidence: 87.4 },
  { type: 'domain', value: 'update-microsoft-cdn.ru', source: 'SpiderFoot OSINT', confidence: 94.0 },
  { type: 'sha256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', source: 'IntelOwl / VirusTotal', confidence: 100.0 },
  { type: 'url',    value: 'http://185.220.101.45/payload.bin', source: 'MalTrail Feed', confidence: 91.2 },
  { type: 'ipv4', value: '185.220.101.46', source: 'OTX AlienVault Pulse', confidence: 96.1 },
  { type: 'domain', value: 'malicious-cdn-eu.xyz',    source: 'CIRCL MISP Taxonomy', confidence: 88.2 },
  { type: 'cve',   value: 'CVE-2024-21887', source: 'CISA KEV List', confidence: 100.0 },
  { type: 'cve',   value: 'CVE-2023-44487', source: 'CISA KEV List', confidence: 100.0 },
];

function IOCExplorer({ iocs }: { iocs: IOC[] }) {
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const data = iocs.length > 0 ? iocs : FALLBACK_IOCS;
  const filtered = data.filter(ioc =>
    (typeFilter === 'all' || ioc.type === typeFilter) &&
    (ioc.value.toLowerCase().includes(filter.toLowerCase()) || ioc.source.toLowerCase().includes(filter.toLowerCase()))
  );
  const confColor = (c: number) => c >= 95 ? '#ef4444' : c >= 80 ? '#f97316' : '#eab308';

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Filter IOCs, domains, hashes..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ flex: 1, minWidth: 180, background: '#0a0a0a', border: '1px solid #1f2937', borderRadius: 8, padding: '8px 14px', color: '#e5e7eb', fontSize: 12, fontFamily: 'monospace', outline: 'none' }}
        />
        {['all', 'ipv4', 'domain', 'sha256', 'url', 'cve'].map(t => (
          <button key={t} onClick={() => setTypeFilter(t)} style={{ padding: '8px 14px', borderRadius: 8, border: `1px solid ${typeFilter === t ? 'var(--onyx-cyan)' : '#1f2937'}`, background: typeFilter === t ? 'rgba(0,238,255,0.08)' : '#0a0a0a', color: typeFilter === t ? '#00eeff' : '#6b7280', fontSize: 11, cursor: 'pointer', textTransform: 'uppercase', fontWeight: 700 }}>
            {t}
          </button>
        ))}
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#22c55e', padding: '8px 0', alignSelf: 'center' }}>
          {filtered.length.toLocaleString()} indicators
        </span>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', borderRadius: 10, border: '1px solid #1f2937' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, fontFamily: 'monospace' }}>
          <thead>
            <tr style={{ background: '#090909', borderBottom: '1px solid #1f2937', position: 'sticky', top: 0, zIndex: 1 }}>
              {['TYPE', 'IOC VALUE', 'SOURCE', 'CONFIDENCE', 'ACTION'].map(h => (
                <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontSize: 10, color: '#4b5563', letterSpacing: '0.08em', fontWeight: 700 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((ioc, i) => (
              <tr key={i} style={{ borderBottom: '1px solid #111', transition: 'background 0.15s' }}
                onMouseEnter={e => (e.currentTarget.style.background = '#0d1117')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                <td style={{ padding: '9px 14px' }}><IOCTypeBadge type={ioc.type} /></td>
                <td style={{ padding: '9px 14px', color: '#e5e7eb', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.value}</td>
                <td style={{ padding: '9px 14px', color: '#6b7280', fontSize: 11 }}>{ioc.source}</td>
                <td style={{ padding: '9px 14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ width: 50, height: 4, background: '#1f2937', borderRadius: 99 }}>
                      <div style={{ width: `${ioc.confidence}%`, height: '100%', background: confColor(ioc.confidence), borderRadius: 99 }} />
                    </div>
                    <span style={{ color: confColor(ioc.confidence), fontSize: 10 }}>{ioc.confidence.toFixed(1)}%</span>
                  </div>
                </td>
                <td style={{ padding: '9px 14px' }}>
                  <button style={{ fontSize: 10, padding: '3px 8px', border: '1px solid #374151', borderRadius: 4, background: 'transparent', color: '#9ca3af', cursor: 'pointer' }}>→ HUNT</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ============================================================================
   Threat Actors Panel
   ============================================================================ */
const THREAT_ACTORS = [
  { name: 'APT29 / Cozy Bear', origin: 'Russian Federation', target: 'Government, Energy', ttp: 'T1078, T1486, T1071', severity: 'critical', campaigns: 14, lastSeen: '2026-04-05', malware: 'SUNBURST, BERSERK BEAR' },
  { name: 'APT41',              origin: 'China',              target: 'Healthcare, Tech',  ttp: 'T1190, T1105, T1566', severity: 'critical', campaigns: 22, lastSeen: '2026-04-04', malware: 'MESSAGETAP, POISONPLUG' },
  { name: 'Lazarus Group',      origin: 'North Korea',        target: 'Finance, Crypto',  ttp: 'T1059, T1055, T1021', severity: 'high',     campaigns: 31, lastSeen: '2026-04-06', malware: 'HOPLIGHT, ELECTRICFISH' },
  { name: 'FIN7',               origin: 'Eastern Europe',     target: 'Retail, Banking',  ttp: 'T1204, T1003, T1112', severity: 'high',     campaigns: 9,  lastSeen: '2026-04-03', malware: 'CARBANAK, GRIFFON' },
  { name: 'Scattered Spider',   origin: 'Unknown',            target: 'Cloud, SaaS',      ttp: 'T1621, T1598, T1538', severity: 'high',     campaigns: 6,  lastSeen: '2026-04-06', malware: 'BlackCat, Muddled Libra' },
  { name: 'Volt Typhoon',       origin: 'China',              target: 'Critical Infrastructure', ttp: 'T1190, T1133', severity: 'critical', campaigns: 7, lastSeen: '2026-04-02', malware: 'KV-Botnet' },
];

function ThreatActorsPanel() {
  const sevColor = (s: string) => ({ critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }[s] || '#6b7280');
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {THREAT_ACTORS.map((actor, i) => (
        <div key={i} className="onyx-card" style={{ borderLeft: `3px solid ${sevColor(actor.severity)}`, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 4 }}>{actor.name}</div>
              <div style={{ fontSize: 11, color: '#6b7280', fontFamily: 'monospace' }}>{actor.origin} · {actor.target}</div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
              <span style={{ fontSize: 9, padding: '2px 8px', borderRadius: 99, border: `1px solid ${sevColor(actor.severity)}`, color: sevColor(actor.severity), textTransform: 'uppercase', fontWeight: 700 }}>{actor.severity}</span>
              <span style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace' }}>Last: {actor.lastSeen}</span>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            <div style={{ fontSize: 10, fontFamily: 'monospace' }}><span style={{ color: '#4b5563' }}>TTPs: </span><span style={{ color: '#f59e0b' }}>{actor.ttp}</span></div>
            <div style={{ fontSize: 10, fontFamily: 'monospace' }}><span style={{ color: '#4b5563' }}>Malware: </span><span style={{ color: '#ef4444' }}>{actor.malware}</span></div>
            <div style={{ fontSize: 10, fontFamily: 'monospace' }}><span style={{ color: '#4b5563' }}>Campaigns: </span><span style={{ color: '#00eeff' }}>{actor.campaigns}</span></div>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ============================================================================
   Crawlers Panel
   ============================================================================ */
const CRAWLER_DEMO = [
  { crawler_id: 'misp-warninglists', status: 'running',  last_run: new Date(Date.now() - 60_000).toISOString(),    iocs_found: 500, source: 'MISP GitHub' },
  { crawler_id: 'spiderfoot-osint',  status: 'idle',     last_run: new Date(Date.now() - 300_000).toISOString(),   iocs_found: 142, source: 'SpiderFoot' },
  { crawler_id: 'maltrail-feed',     status: 'running',  last_run: new Date(Date.now() - 30_000).toISOString(),    iocs_found: 87,  source: 'MalTrail' },
  { crawler_id: 'intelowl-api',      status: 'error',    last_run: new Date(Date.now() - 3600_000).toISOString(),  iocs_found: 0,   source: 'IntelOwl' },
  { crawler_id: 'otx-pulses',        status: 'idle',     last_run: new Date(Date.now() - 900_000).toISOString(),   iocs_found: 233, source: 'AlienVault OTX' },
  { crawler_id: 'sigma-rules-feed',  status: 'running',  last_run: new Date(Date.now() - 15_000).toISOString(),    iocs_found: 44,  source: 'Sigma HQ' },
];

function CrawlersPanel({ crawlers }: { crawlers?: typeof CRAWLER_DEMO }) {
  const data = crawlers && crawlers.length > 0 ? crawlers : CRAWLER_DEMO;
  const statusColors: Record<string, string> = { running: '#22c55e', idle: '#00eeff', error: '#ef4444', stopped: '#4b5563' };
  const totalIocs = data.reduce((s, c) => s + ((c as any).iocs_found || 0), 0);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {[
          { label: 'Active Crawlers', value: data.filter(c => c.status === 'running').length, color: '#22c55e' },
          { label: 'Total IOCs Harvested', value: totalIocs.toLocaleString(), color: '#00eeff' },
          { label: 'Failed Connectors', value: data.filter(c => c.status === 'error').length, color: '#ef4444' },
        ].map(kpi => (
          <div key={kpi.label} className="onyx-card" style={{ textAlign: 'center', borderBottom: `2px solid ${kpi.color}` }}>
            <div style={{ fontSize: 22, fontWeight: 800, color: kpi.color, fontFamily: 'monospace' }}>{kpi.value}</div>
            <div style={{ fontSize: 10, color: '#6b7280', marginTop: 4, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{kpi.label}</div>
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {data.map((c, i) => (
          <div key={i} className="onyx-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: statusColors[c.status] || '#4b5563', boxShadow: c.status === 'running' ? `0 0 8px ${statusColors.running}` : undefined }} />
              <div>
                <div style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 600 }}>{c.crawler_id}</div>
                <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#6b7280' }}>{(c as any).source}</div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 24, alignItems: 'center' }}>
              <div style={{ fontSize: 11, fontFamily: 'monospace', textAlign: 'right' }}>
                <div style={{ color: '#00eeff', fontWeight: 700 }}>{(c as any).iocs_found?.toLocaleString() || '—'} IOCs</div>
                <div style={{ color: '#4b5563', fontSize: 10 }}>{c.last_run ? new Date(c.last_run).toLocaleTimeString('en-US', { hour12: false }) : '—'}</div>
              </div>
              <span style={{ fontSize: 10, padding: '3px 10px', border: `1px solid ${statusColors[c.status]}`, borderRadius: 99, color: statusColors[c.status], textTransform: 'uppercase', fontWeight: 700 }}>{c.status}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============================================================================
   Reports Panel
   ============================================================================ */
const REPORTS_DEMO = [
  { id: 'RPT-2026-001', title: 'APT29 Targeting EU Critical Infrastructure', severity: 'critical', date: '2026-04-05', iocs: 48,  ttps: 12, author: 'ONYX NLP Engine' },
  { id: 'RPT-2026-002', title: 'Lazarus Group Crypto Exchange Campaign',      severity: 'high',     date: '2026-04-04', iocs: 31,  ttps: 8,  author: 'ONYX NLP Engine' },
  { id: 'RPT-2026-003', title: 'FIN7 POS Malware Wave — Retail Sector',       severity: 'high',     date: '2026-04-03', iocs: 22,  ttps: 6,  author: 'Analyst Review' },
  { id: 'RPT-2026-004', title: 'Volt Typhoon Living-off-the-Land Techniques', severity: 'critical', date: '2026-04-02', iocs: 19,  ttps: 14, author: 'ONYX NLP Engine' },
  { id: 'RPT-2026-005', title: 'MISP Warninglist Q1 2026 Digest',             severity: 'medium',   date: '2026-04-01', iocs: 500, ttps: 3,  author: 'Auto-Ingestion' },
];

function ReportsPanel() {
  const sevColor = (s: string) => ({ critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }[s] || '#6b7280');
  const [synthesisId, setSynthesisId] = useState<string | null>(null);

  const handleExportPDF = (r: typeof REPORTS_DEMO[0]) => {
    const doc = new jsPDF();
    doc.setFont("courier");
    doc.setFontSize(20);
    doc.text(`ONYX CTI EXECUTIVE REPORT: ${r.id}`, 20, 20);
    doc.setFontSize(12);
    doc.text(`Title: ${r.title}`, 20, 35);
    doc.text(`Severity: ${r.severity.toUpperCase()}`, 20, 45);
    doc.text(`Date: ${r.date}`, 20, 55);
    doc.text(`Author: ${r.author}`, 20, 65);
    doc.text(`Associated IOCs: ${r.iocs}`, 20, 75);
    doc.text(`Associated TTPs (MITRE ATT&CK): ${r.ttps}`, 20, 85);
    doc.setLineWidth(0.5);
    doc.line(20, 90, 190, 90);
    doc.text("EXECUTIVE SYNTHESIS", 20, 100);
    doc.setFontSize(10);
    const txt = `This report details the ${r.title} campaign identified on ${r.date}. Analysis reveals ${r.iocs} confirmed IOCs and ${r.ttps} MITRE ATT&CK techniques. Severity level: ${r.severity.toUpperCase()}. Immediate network isolation of affected segments is required.`;
    doc.text(doc.splitTextToSize(txt, 170), 20, 110);
    doc.save(`${r.id}_Executive_Report.pdf`);
  };

  const handleExportCSV = (r: typeof REPORTS_DEMO[0]) => {
    const blob = new Blob([Papa.unparse([r])], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${r.id}_Export.csv`;
    link.click();
  };

  const handleExportJSON = (r: typeof REPORTS_DEMO[0]) => {
    const stixBundle = {
      type: "bundle", spec_version: "2.1",
      id: `bundle--${crypto.randomUUID()}`,
      objects: [{ type: "report", spec_version: "2.1", id: `report--${crypto.randomUUID()}`, created: new Date().toISOString(), modified: new Date().toISOString(), name: r.title, description: `Severity: ${r.severity} | IOCs: ${r.iocs} | TTPs: ${r.ttps}`, report_types: ["threat-actor"], published: r.date, object_refs: [] }]
    };
    const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: 'application/json' });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${r.id}_STIX21.json`;
    link.click();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {REPORTS_DEMO.map((r, i) => (
        <div key={i} className="onyx-card" style={{ display: 'flex', flexDirection: 'column', padding: 16, borderLeft: `3px solid ${sevColor(r.severity)}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ flex: 1, marginRight: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#4b5563' }}>{r.id}</span>
                <span style={{ fontSize: 9, padding: '2px 8px', borderRadius: 99, border: `1px solid ${sevColor(r.severity)}`, color: sevColor(r.severity), textTransform: 'uppercase', fontWeight: 700 }}>{r.severity}</span>
              </div>
              <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>{r.title}</div>
              <div style={{ fontSize: 11, color: '#4b5563', fontFamily: 'monospace' }}>
                {r.author} · {r.date} · <span style={{ color: '#00eeff' }}>{r.iocs} IOCs</span> · <span style={{ color: '#f59e0b' }}>{r.ttps} TTPs</span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end', width: '280px' }}>
              <button onClick={() => setSynthesisId(synthesisId === r.id ? null : r.id)} style={{ fontSize: 10, padding: '6px 10px', background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.4)', borderRadius: 6, color: '#a855f7', cursor: 'pointer', fontWeight: 'bold' }}>⚡ WAR ROOM BRIEF</button>
              <button onClick={() => handleExportPDF(r)} style={{ fontSize: 10, padding: '6px 10px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.4)', borderRadius: 6, color: '#ef4444', cursor: 'pointer' }}>PDF</button>
              <button onClick={() => handleExportCSV(r)} style={{ fontSize: 10, padding: '6px 10px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.4)', borderRadius: 6, color: '#22c55e', cursor: 'pointer' }}>CSV</button>
              <button onClick={() => handleExportJSON(r)} style={{ fontSize: 10, padding: '6px 10px', background: 'rgba(0,238,255,0.1)', border: '1px solid rgba(0,238,255,0.4)', borderRadius: 6, color: '#00eeff', cursor: 'pointer' }}>STIX 2.1</button>
            </div>
          </div>
          {synthesisId === r.id && (
            <IntelligenceBrief report={r} onClose={() => setSynthesisId(null)} />
          )}
        </div>
      ))}
    </div>
  );
}

/* ============================================================================
   Main Dashboard — Client Entry Point
   ============================================================================ */
export default function DashboardClient() {
  const [stats, setStats]         = useState<DashboardStats | null>(null);
  const [armedIocs, setArmedIocs] = useState<IOC[]>([]);
  const [activeTab, setActiveTab] = useState('overview');
  const { events, connected, liveIocCount } = useSSE(`${API}/api/v1/dashboard/events/stream`);

  const loadStats = useCallback(async () => {
    const data = await apiFetch<DashboardStats>('/api/v1/dashboard/stats');
    if (data) setStats(data);
    const iocData = await apiFetch<{ total: number; iocs: IOC[] }>('/api/v1/iocs/armed');
    if (iocData?.iocs) setArmedIocs(iocData.iocs);
  }, []);

  useEffect(() => {
    loadStats();
    // 15s refresh — fast enough to show drift without hammering the API
    const interval = setInterval(loadStats, 15_000);
    return () => clearInterval(interval);
  }, [loadStats]);

  // ── Live-updated KPIs ────────────────────────────────────────────────────
  // Base from API, enriched with SSE live counter
  const baseIocTotal = stats?.iocs?.total_iocs?.value || armedIocs.length || FALLBACK_IOCS.length;
  const iocTotal    = baseIocTotal + liveIocCount;
  const threatTotal = stats?.threats?.total_threats?.value || THREAT_ACTORS.length;
  const stixTotal   = stats?.stix?.total || (iocTotal + 42);
  const avgConf     = Math.round(stats?.iocs?.avg_confidence?.value || 97.8);
  const severities  = stats?.iocs?.by_severity?.buckets || [
    { key: 'critical', doc_count: 127 + Math.floor(liveIocCount * 0.3) },
    { key: 'high',     doc_count: 244 + Math.floor(liveIocCount * 0.5) },
    { key: 'medium',   doc_count: 89  + Math.floor(liveIocCount * 0.15) },
    { key: 'low',      doc_count: 34  + Math.floor(liveIocCount * 0.05) },
  ];
  const sevTotal = severities.reduce((s, d) => s + d.doc_count, 0) || 1;
  const liveEvents = events.filter(e => e.type === 'ioc_detected');
  const nlpEvents = events.filter(e => e.type === 'nlp_extraction');

  return (
    <div className="onyx-layout">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />
      <Header connected={connected} />
      <main className="onyx-main">
        {/* ====== OVERVIEW ====== */}
        {activeTab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
              <StatCard label="Total IOCs Armed" value={iocTotal} trend={`+${liveIocCount} Live`} icon="⬡" color="var(--onyx-cyan)" />
              <StatCard label="Active Threat Actors" value={threatTotal} trend="+2 new" icon="☠" color="#ef4444" />
              <StatCard label="STIX Objects" value={stixTotal} icon="◎" color="var(--onyx-magenta)" />
              <StatCard label="Engine Confidence" value={`${avgConf}%`} icon="◈" color="#22c55e" />
            </div>

            {/* 3D Map — fully CSR-only (never rendered server-side) */}
            <ThreatMap3D />

            {/* AI & SIEM Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <SciBERTEnginePanel />
              <SIEMRuleConverter />
            </div>

            {/* Bottom Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
              <div className="onyx-card">
                <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, marginBottom: 14 }}>Severity Distribution</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {severities.map(s => <SeverityBar key={s.key} severity={s.key} count={s.doc_count} total={sevTotal} />)}
                </div>
              </div>
              <div className="onyx-card">
                <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, marginBottom: 14 }}>🕸 Crawlers</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {CRAWLER_DEMO.slice(0, 4).map((c, i) => (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid #111' }}>
                      <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{c.crawler_id}</span>
                      <span style={{ fontSize: 10, color: c.status === 'running' ? '#22c55e' : c.status === 'error' ? '#ef4444' : '#00eeff', textTransform: 'uppercase', fontWeight: 700 }}>{c.status}</span>
                    </div>
                  ))}
                </div>
              </div>
              <LiveFeed events={liveEvents.length ? liveEvents : events} />
            </div>
          </div>
        )}

        {activeTab === 'iocs' && (
          <div style={{ height: 'calc(100vh - 120px)' }}>
            <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 20, background: 'linear-gradient(135deg, var(--onyx-cyan), var(--onyx-green))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              ⬡ IOC Explorer — MISP / OTX Live Feed
            </h2>
            <IOCExplorer iocs={armedIocs} />
          </div>
        )}

        {activeTab === 'threats' && (
          <div>
            <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 20, background: 'linear-gradient(135deg, #ef4444, #f97316)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              ☠ Threat Actor Intelligence
            </h2>
            <ThreatActorsPanel />
          </div>
        )}

        {/* 3D STIX Graph — fully CSR-only */}
        {activeTab === 'graph' && <ThreatGraph />}

        {/* ====== AI LAB ====== */}
        {activeTab === 'ailab' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2 style={{ fontSize: 22, fontWeight: 800, background: 'linear-gradient(135deg, #a855f7, #00f0ff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', marginBottom: 4 }}>
                  ⟁ AI Intelligence Lab
                </h2>
                <p style={{ fontSize: 12, color: '#4b5563', fontFamily: 'monospace' }}>
                  SciBERT NLP Engine · MITRE ATT&CK Mapper · STIX 2.1 Export · Real-time IOC Extraction
                </p>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <div style={{ fontSize: 10, padding: '4px 12px', background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.3)', borderRadius: 99, color: '#a855f7', fontFamily: 'monospace' }}>MODEL: scibert-scivocab-uncased</div>
                <div style={{ fontSize: 10, padding: '4px 12px', background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.3)', borderRadius: 99, color: '#00f0ff', fontFamily: 'monospace' }}>CORPUS: MITRE ATT&CK v14</div>
              </div>
            </div>
            <NLPAnalyzer liveEvents={nlpEvents} />
          </div>
        )}

        {activeTab === 'crawlers' && (
          <div>
            <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 20, background: 'linear-gradient(135deg, #22c55e, #00eeff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              🕸 Crawler Operations Center
            </h2>
            <CrawlersPanel crawlers={stats?.crawlers as any} />
          </div>
        )}

        {activeTab === 'reports' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: 22, fontWeight: 800, background: 'linear-gradient(135deg, #a855f7, var(--onyx-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                📋 Threat Intelligence Reports
              </h2>
              <button style={{ padding: '8px 18px', background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.4)', borderRadius: 8, color: '#a855f7', fontSize: 12, cursor: 'pointer', fontWeight: 700 }}>
                + New Report
              </button>
            </div>
            <ReportsPanel />
          </div>
        )}

        {activeTab === 'attack' && <AttackMatrix />}
      </main>
      
      {/* GLOBAL AGENT COPILOT */}
      <AgenticCopilot />
    </div>
  );
}
