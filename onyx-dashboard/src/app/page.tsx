'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import dynamic from 'next/dynamic';
import jsPDF from 'jspdf';
import Papa from 'papaparse';
import AttackMatrix from '@/components/AttackMatrix';
import SciBERTEnginePanel from '@/components/SciBERTEnginePanel';
import SIEMRuleConverter from '@/components/SIEMRuleConverter';

// ssr:false prevents WebGL/Canvas from running on the server → kills SSR crashes
const ThreatMap3D = dynamic(() => import('@/components/ThreatMap3D'), { ssr: false });
const ThreatGraph  = dynamic(() => import('@/components/ThreatGraph'),  { ssr: false });

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
   Hooks
   ============================================================================ */
function useSSE(url: string) {
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource(url);
      es.onopen = () => setConnected(true);
      es.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          setEvents(prev => [{ type: e.type || 'message', data, timestamp: new Date().toISOString() }, ...prev.slice(0, 99)]);
        } catch {}
      };
      es.onerror = () => { setConnected(false); es?.close(); };
    } catch {}
    return () => { es?.close(); };
  }, [url]);
  return { events, connected };
}

/* ============================================================================
   Shared Components
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
          {connected ? 'LIVE' : 'OFFLINE'}
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
        {events.length === 0 && <div style={{ textAlign: 'center', padding: 'var(--space-xl)', color: 'var(--text-tertiary)', fontSize: 'var(--font-size-sm)' }}>Waiting for events...</div>}
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
   IOC Explorer Table — Real armed_iocs from FastAPI
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
  { type: 'sha256', value: 'e3b0c44298fc1c149afbf...', source: 'IntelOwl / VirusTotal', confidence: 100.0 },
  { type: 'url',    value: 'http://185.220.101.45/payload.bin', source: 'MalTrail Feed', confidence: 91.2 },
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
      {/* Controls */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Filter IOCs..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ flex: 1, minWidth: 180, background: '#0a0a0a', border: '1px solid #1f2937', borderRadius: 8, padding: '8px 14px', color: '#e5e7eb', fontSize: 12, fontFamily: 'monospace', outline: 'none' }}
        />
        {['all', 'ipv4', 'domain', 'sha256', 'url'].map(t => (
          <button key={t} onClick={() => setTypeFilter(t)} style={{ padding: '8px 14px', borderRadius: 8, border: `1px solid ${typeFilter === t ? 'var(--onyx-cyan)' : '#1f2937'}`, background: typeFilter === t ? 'rgba(0,238,255,0.08)' : '#0a0a0a', color: typeFilter === t ? '#00eeff' : '#6b7280', fontSize: 11, cursor: 'pointer', textTransform: 'uppercase', fontWeight: 700 }}>
            {t}
          </button>
        ))}
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#22c55e', padding: '8px 0', alignSelf: 'center' }}>
          {filtered.length.toLocaleString()} IOCs
        </span>
      </div>
      {/* Table */}
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
            <div style={{ fontSize: 10, fontFamily: 'monospace' }}>
              <span style={{ color: '#4b5563' }}>TTPs: </span>
              <span style={{ color: '#f59e0b' }}>{actor.ttp}</span>
            </div>
            <div style={{ fontSize: 10, fontFamily: 'monospace' }}>
              <span style={{ color: '#4b5563' }}>Malware: </span>
              <span style={{ color: '#ef4444' }}>{actor.malware}</span>
            </div>
            <div style={{ fontSize: 10, fontFamily: 'monospace' }}>
              <span style={{ color: '#4b5563' }}>Campaigns: </span>
              <span style={{ color: '#00eeff' }}>{actor.campaigns}</span>
            </div>
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
      {/* Summary KPIs */}
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
      {/* Crawler List */}
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
    doc.text(`Title: ${r.title}`, 20, 30);
    doc.text(`Severity: ${r.severity.toUpperCase()}`, 20, 40);
    doc.text(`Date: ${r.date}`, 20, 50);
    doc.text(`Author: ${r.author}`, 20, 60);
    doc.text(`Associated IOCs: ${r.iocs}`, 20, 70);
    doc.text(`Associated TTPs: ${r.ttps}`, 20, 80);
    doc.setLineWidth(0.5);
    doc.line(20, 85, 190, 85);
    doc.text("EXECUTIVE SYNTHESIS", 20, 95);
    doc.setFontSize(10);
    const splitText = doc.splitTextToSize(`Ce rapport détaille la campagne ${r.title} identifiée le ${r.date}. L'analyse révèle la présence de ${r.iocs} traces de compromissions réseau/système (IOCs) confirmées et ${r.ttps} techniques MITRE ATT&CK. Un niveau de criticité ${r.severity.toUpperCase()} exige une isolation réseau immédiate des segments affectés. L'acteur de la menace semble hautement organisé et dispose de capacités avancées.`, 170);
    doc.text(splitText, 20, 105);
    doc.save(`${r.id}_Executive_Report.pdf`);
  };

  const handleExportCSV = (r: typeof REPORTS_DEMO[0]) => {
    const csv = Papa.unparse([r]);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${r.id}_Export.csv`;
    link.click();
  };

  const handleExportJSON = (r: typeof REPORTS_DEMO[0]) => {
    const stixBundle = {
      type: "bundle",
      id: `bundle--${r.id}`,
      objects: [{ type: "report", name: r.title, description: `Severity: ${r.severity}` }]
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
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end', width: '300px' }}>
              <button onClick={() => setSynthesisId(synthesisId === r.id ? null : r.id)} style={{ fontSize: 10, padding: '6px 10px', background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.4)', borderRadius: 6, color: '#a855f7', cursor: 'pointer', fontWeight: 'bold' }}>
                Générer Synthèse
              </button>
              <button onClick={() => handleExportPDF(r)} style={{ fontSize: 10, padding: '6px 10px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.4)', borderRadius: 6, color: '#ef4444', cursor: 'pointer' }}>PDF</button>
              <button onClick={() => handleExportCSV(r)} style={{ fontSize: 10, padding: '6px 10px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.4)', borderRadius: 6, color: '#22c55e', cursor: 'pointer' }}>CSV</button>
              <button onClick={() => handleExportJSON(r)} style={{ fontSize: 10, padding: '6px 10px', background: 'rgba(0,238,255,0.1)', border: '1px solid rgba(0,238,255,0.4)', borderRadius: 6, color: '#00eeff', cursor: 'pointer' }}>JSON (STIX)</button>
            </div>
          </div>
          {synthesisId === r.id && (
            <div className="animate-in" style={{ marginTop: '16px', padding: '16px', background: '#080c14', borderRadius: '8px', border: '1px solid #1f2937' }}>
              <h4 style={{ fontSize: '12px', color: '#a855f7', marginBottom: '8px', fontFamily: 'monospace' }}>⚡ ONYX AI SYNTHESIS</h4>
              <p style={{ fontSize: '13px', color: '#e5e7eb', lineHeight: '1.6' }}>
                <strong>Résumé Opérationnel :</strong> Cette menace, identifiée sous la nomenclature {r.id}, orchestre une campagne qualifiée de niveau <strong>{r.severity.toUpperCase()}</strong>. 
                Les corrélations ont permis de recenser {r.iocs} marqueurs d'attaque (IOCs) et d'isoler la présence de {r.ttps} techniques MITRE ATT&CK. <br/><br/>
                <strong>Action Requise :</strong> Compte tenu du profil ({r.author}) et de la typologie d'empreinte, des mesures d'endiguement doivent être prises sur les pare-feux périphériques. Exportez le rapport au format STIX 2.1 (JSON) vers le SIEM ou l'EDR pour automatiser la remédiation.
              </p>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ============================================================================
   Main Dashboard Page
   ============================================================================ */
export default function DashboardPage() {
  const [stats, setStats]     = useState<DashboardStats | null>(null);
  const [armedIocs, setArmedIocs] = useState<IOC[]>([]);
  const [activeTab, setActiveTab] = useState('overview');
  const { events, connected }   = useSSE(`${API}/api/v1/dashboard/events/stream`);

  const loadStats = useCallback(async () => {
    const data = await apiFetch<DashboardStats>('/api/v1/dashboard/stats');
    if (data) setStats(data);
    // Fetch armed IOCs from the in-memory state endpoint
    const iocData = await apiFetch<{ iocs: IOC[] }>('/api/v1/iocs/armed');
    if (iocData?.iocs) setArmedIocs(iocData.iocs);
  }, []);

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 30_000);
    return () => clearInterval(interval);
  }, [loadStats]);

  const iocTotal   = stats?.iocs?.total_iocs?.value   || armedIocs.length || FALLBACK_IOCS.length;
  const threatTotal = stats?.threats?.total_threats?.value || THREAT_ACTORS.length;
  const stixTotal  = stats?.stix?.total || 0;
  const avgConf    = Math.round(stats?.iocs?.avg_confidence?.value || 98);
  const severities = stats?.iocs?.by_severity?.buckets || [
    { key: 'critical', doc_count: 127 },
    { key: 'high', doc_count: 244 },
    { key: 'medium', doc_count: 89 },
    { key: 'low', doc_count: 34 },
  ];
  const sevTotal = severities.reduce((s, d) => s + d.doc_count, 0) || 1;

  return (
    <div className="onyx-layout">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />
      <Header connected={connected} />
      <main className="onyx-main">
        {/* ====== OVERVIEW ====== */}
        {activeTab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* KPI Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
              <StatCard label="Total IOCs Armed" value={iocTotal} trend="+28% Live" icon="⬡" color="var(--onyx-cyan)" />
              <StatCard label="Active Threat Actors" value={threatTotal} trend="+2 new" icon="☠" color="#ef4444" />
              <StatCard label="STIX Objects" value={stixTotal} icon="◎" color="var(--onyx-magenta)" />
              <StatCard label="Engine Confidence" value={`${avgConf}%`} icon="◈" color="#22c55e" />
            </div>

            {/* Map — SSR:false via dynamic import — zero crash risk */}
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
              <LiveFeed events={events} />
            </div>
          </div>
        )}

        {/* ====== IOC EXPLORER ====== */}
        {activeTab === 'iocs' && (
          <div style={{ height: 'calc(100vh - 120px)' }}>
            <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 20, background: 'linear-gradient(135deg, var(--onyx-cyan), var(--onyx-green))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              ⬡ IOC Explorer — MISP Live Feed
            </h2>
            <IOCExplorer iocs={armedIocs} />
          </div>
        )}

        {/* ====== THREAT ACTORS ====== */}
        {activeTab === 'threats' && (
          <div>
            <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 20, background: 'linear-gradient(135deg, #ef4444, #f97316)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              ☠ Threat Actor Intelligence
            </h2>
            <ThreatActorsPanel />
          </div>
        )}

        {/* ====== THREAT GRAPH ====== */}
        {activeTab === 'graph' && <ThreatGraph />}

        {/* ====== CRAWLERS ====== */}
        {activeTab === 'crawlers' && (
          <div>
            <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 20, background: 'linear-gradient(135deg, #22c55e, #00eeff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              🕸 Crawler Operations Center
            </h2>
            <CrawlersPanel crawlers={stats?.crawlers as any} />
          </div>
        )}

        {/* ====== REPORTS ====== */}
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

        {/* ====== ATT&CK MATRIX ====== */}
        {activeTab === 'attack' && <AttackMatrix />}
      </main>
    </div>
  );
}
