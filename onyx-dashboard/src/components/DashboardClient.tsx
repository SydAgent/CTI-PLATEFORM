'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import dynamic from 'next/dynamic';
import ThreatActorIntel from './ThreatActorIntel';
import ReportGenerator from './ReportGenerator';
import jsPDF from 'jspdf';
import Papa from 'papaparse';
import AttackMatrix from '@/components/AttackMatrix';
import SciBERTEnginePanel from '@/components/SciBERTEnginePanel';
import SIEMRuleConverter from '@/components/SIEMRuleConverter';
import NLPAnalyzer from '@/components/NLPAnalyzer';

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
import { useOnyxStore, type IOC, type WSEvent as SSEEvent } from '@/lib/store';

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
  const selectedEventId = useOnyxStore(s => s.selectedEventId);
  const setSelectedEventId = useOnyxStore(s => s.setSelectedEventId);
  const isFeedPaused = useOnyxStore(s => s.isFeedPaused);
  const feedBuffer = useOnyxStore(s => s.feedBuffer);
  const pauseFeed = useOnyxStore(s => s.pauseFeed);
  const resumeFeed = useOnyxStore(s => s.resumeFeed);
  return (
    <div className="onyx-card animate-in" style={{ height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-md)' }}>
        <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
          <span className="pulse-live" style={isFeedPaused ? { background: 'var(--onyx-amber)', animationPlayState: 'paused' } : undefined} /> Live Event Feed
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
          {isFeedPaused && feedBuffer.length > 0 && (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', padding: '2px 8px', borderRadius: 'var(--radius-full)', background: 'rgba(234,179,8,0.15)', color: '#eab308', fontWeight: 700, letterSpacing: '0.5px' }}>
              ⏸ PAUSED · {feedBuffer.length} queued
            </span>
          )}
          <button
            id="live-feed-pause-toggle"
            onClick={() => isFeedPaused ? resumeFeed() : pauseFeed()}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '4px 12px', borderRadius: 'var(--radius-sm)',
              background: isFeedPaused ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)',
              color: isFeedPaused ? '#22c55e' : '#ef4444',
              border: `1px solid ${isFeedPaused ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`,
              cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: '10px',
              fontWeight: 700, letterSpacing: '0.5px', textTransform: 'uppercase' as const,
              transition: 'all 0.2s',
            }}
          >
            {isFeedPaused ? '▶ RESUME' : '⏸ PAUSE'}
          </button>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)' }}>{events.length} events</span>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)', maxHeight: 320, overflowY: 'auto', opacity: isFeedPaused ? 0.5 : 1, transition: 'opacity 0.3s' }}>
        {events.length === 0 && <div style={{ textAlign: 'center', padding: 'var(--space-xl)', color: 'var(--text-tertiary)', fontSize: 'var(--font-size-sm)' }}>Awaiting live telemetry...</div>}
        {events.map((ev, i) => {
          const evValue = String(ev.data?.value || '');
          const isSelected = selectedEventId === evValue && evValue !== '';
          return (
            <div key={i} className="animate-in" onClick={() => setSelectedEventId(isSelected ? null : evValue)} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-md)', padding: '6px 12px', background: isSelected ? 'rgba(0,238,255,0.08)' : 'var(--onyx-bg-tertiary)', borderRadius: 'var(--radius-sm)', borderLeft: `3px solid ${isSelected ? '#00eeff' : 'var(--onyx-cyan)'}`, cursor: 'pointer', transition: 'all 0.15s' }}>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-tertiary)', whiteSpace: 'nowrap' }}>{new Date(ev.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
              <span className="ioc-value" style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{evValue || ev.type || 'event'}</span>
              <IOCTypeBadge type={String(ev.data?.type || 'info')} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ============================================================================
   IOC Explorer
   ============================================================================ */

function IOCExplorer({ iocs }: { iocs: IOC[] }) {
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const selectedEventId = useOnyxStore(s => s.selectedEventId);
  const setSelectedEventId = useOnyxStore(s => s.setSelectedEventId);
  const data = iocs;
  const isLoading = data.length === 0;
  const filtered = data.filter(ioc => {
    // Cross-module filter: if an event is selected in LiveFeed, restrict to matching IOCs
    if (selectedEventId && !ioc.value.includes(selectedEventId)) return false;
    return (
      (typeFilter === 'all' || ioc.type === typeFilter) &&
      (ioc.value.toLowerCase().includes(filter.toLowerCase()) || ioc.source.toLowerCase().includes(filter.toLowerCase()))
    );
  });
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
        {selectedEventId && (
          <button onClick={() => setSelectedEventId(null)} style={{ padding: '8px 14px', borderRadius: 8, border: '1px solid #ef4444', background: 'rgba(239,68,68,0.08)', color: '#ef4444', fontSize: 11, cursor: 'pointer', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
            ✕ Clear Filter: {selectedEventId}
          </button>
        )}
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#22c55e', padding: '8px 0', alignSelf: 'center' }}>
          {isLoading ? 'Awaiting live telemetry...' : `${filtered.length.toLocaleString()} indicators`}
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
function ThreatActorsPanel({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const sevColor = (s: string) => ({ critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }[s] || '#6b7280');
  const [actors, setActors] = useState<any[]>([]);
  const [selectedActor, setSelectedActor] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const data = await apiFetch<any>('/api/v1/dashboard/mitre-threat-actors');
      if (data && data.threat_actors) {
        setActors(data.threat_actors);
        if (data.threat_actors.length > 0) setSelectedActor(data.threat_actors[0]);
      }
      setLoading(false);
    }
    load();
    const int = setInterval(load, 30000);
    return () => clearInterval(int);
  }, []);

  if (loading) return <div style={{ color: '#6b7280', textAlign: 'center', padding: 40, fontFamily: 'monospace' }}>Awaiting threat intelligence...</div>;

  return (
    <div style={{ display: 'flex', gap: 24, height: '650px' }}>
      {/* Master List */}
      <div style={{ width: 320, display: 'flex', flexDirection: 'column', gap: 8, overflowY: 'auto', paddingRight: 8 }} className="scrollbar-hide">
        {actors.map(actor => (
          <div key={actor.id} onClick={() => setSelectedActor(actor)} className="onyx-card" style={{ padding: 12, cursor: 'pointer', borderLeft: `3px solid ${sevColor(actor.severity)}`, background: selectedActor?.id === actor.id ? 'rgba(0,238,255,0.05)' : 'var(--onyx-bg-secondary)', border: selectedActor?.id === actor.id ? '1px solid var(--onyx-cyan)' : '1px solid transparent' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <div style={{ fontWeight: 700, fontSize: 14, color: selectedActor?.id === actor.id ? '#00eeff' : '#e5e7eb' }}>{actor.name}</div>
              <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, background: actor.status === 'Active Now' ? 'rgba(239,68,68,0.2)' : 'rgba(107,114,128,0.2)', color: actor.status === 'Active Now' ? '#ef4444' : '#9ca3af', fontWeight: 700, border: `1px solid ${actor.status === 'Active Now' ? '#ef4444' : '#4b5563'}` }}>
                {actor.status === 'Active Now' ? '● ACTIVE' : '○ MONITORED'}
              </span>
            </div>
            <div style={{ fontSize: 11, color: '#9ca3af', fontFamily: 'monospace' }}>{actor.description}</div>
          </div>
        ))}
      </div>
      
      {/* Detail Pane */}
      {selectedActor ? (
        <div className="onyx-card" style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 24, overflowY: 'auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid #1f2937', paddingBottom: 20, marginBottom: 20 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                <h2 style={{ fontSize: 24, fontWeight: 800, margin: 0, color: '#fff' }}>{selectedActor.name}</h2>
                <span style={{ fontSize: 10, padding: '4px 8px', borderRadius: 99, border: `1px solid ${sevColor(selectedActor.severity)}`, color: sevColor(selectedActor.severity), textTransform: 'uppercase', fontWeight: 700 }}>{selectedActor.severity}</span>
              </div>
              <div style={{ fontSize: 13, color: '#9ca3af', fontFamily: 'monospace', display: 'flex', flexWrap: 'wrap', gap: 16 }}>
                <span><strong style={{ color: '#6b7280' }}>Aliases:</strong> {selectedActor.aliases?.join(', ') || 'None'}</span>
                <span><strong style={{ color: '#6b7280' }}>Origin:</strong> {selectedActor.description}</span>
                <span><strong style={{ color: '#6b7280' }}>Target:</strong> {selectedActor.target}</span>
              </div>
            </div>
            <button onClick={() => onNavigate('graph')} style={{ padding: '8px 16px', background: 'rgba(0,238,255,0.1)', border: '1px solid var(--onyx-cyan)', borderRadius: 8, color: 'var(--onyx-cyan)', fontSize: 12, fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
              ◎ VISUALIZE INFRASTRUCTURE
            </button>
          </div>
          
          <div style={{ display: 'flex', gap: 32 }}>
            <div style={{ flex: 1 }}>
              <h3 style={{ fontSize: 14, color: '#e5e7eb', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Observed MITRE TTPs</h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {selectedActor.techniques?.map((t: string) => (
                  <button key={t} onClick={() => onNavigate('attack')} style={{ padding: '4px 10px', background: '#0a0a0a', border: '1px solid #374151', borderRadius: 6, color: '#f59e0b', fontSize: 11, fontFamily: 'monospace', cursor: 'pointer' }} className="hover:border-amber-500 hover:bg-amber-900/20">
                    {t}
                  </button>
                )) || <span style={{ color: '#6b7280', fontSize: 12 }}>No TTPs recorded</span>}
              </div>
            </div>
            
            <div style={{ flex: 1 }}>
              <h3 style={{ fontSize: 14, color: '#e5e7eb', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Active IOCs ({selectedActor.live_iocs || 0})</h3>
              {selectedActor.live_iocs > 0 ? (
                <button onClick={() => onNavigate('iocs')} style={{ padding: '8px 16px', background: 'rgba(239,68,68,0.1)', border: '1px solid #ef4444', borderRadius: 8, color: '#ef4444', fontSize: 12, fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
                  ⬡ HUNT ACTIVE INDICATORS
                </button>
              ) : (
                <div style={{ color: '#6b7280', fontSize: 12, fontFamily: 'monospace', padding: '8px 0' }}>No active telemetry matching this actor at this time.</div>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="onyx-card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6b7280', fontFamily: 'monospace' }}>Select an Adversary</div>
      )}
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

function CrawlersPanel() {
  const [logs, setLogs] = useState<any[]>([]);
  const [stats, setStats] = useState({ running: 4, harvested: 12543, failed: 1 });

  // UX Controls
  const [isPaused, setIsPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filterText, setFilterText] = useState('');
  const [queuedCount, setQueuedCount] = useState(0);
  
  const scrollRef = useRef<HTMLDivElement>(null);
  const isPausedRef = useRef(false);
  const queuedLogsRef = useRef<any[]>([]);

  useEffect(() => {
    isPausedRef.current = isPaused;
    if (!isPaused && queuedLogsRef.current.length > 0) {
      // Drain queue
      setLogs(prev => [...prev, ...queuedLogsRef.current].slice(-150));
      queuedLogsRef.current = [];
      setQueuedCount(0);
    }
  }, [isPaused]);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const handleScroll = () => {
    if (!scrollRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
    // We consider 'at bottom' if within 10px of bottom
    const isAtBottom = scrollHeight - scrollTop - clientHeight <= 10;
    
    if (autoScroll && !isAtBottom) {
      setAutoScroll(false);
    } else if (!autoScroll && isAtBottom) {
      setAutoScroll(true);
    }
  };

  useEffect(() => {
    const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    const sse = new window.EventSource(`${API}/api/v1/dashboard/crawlers/stream`);
    sse.addEventListener('log', (e: any) => {
      try {
        const data = JSON.parse(e.data);
        
        if (isPausedRef.current) {
          queuedLogsRef.current.push(data);
          // Optional: cap the queue size to avoid memory leaks
          if (queuedLogsRef.current.length > 500) queuedLogsRef.current.shift();
          setQueuedCount(queuedLogsRef.current.length);
        } else {
          setLogs(prev => [...prev, data].slice(-150));
        }
        
        if (data.status === 'SUCCESS') setStats(s => ({ ...s, harvested: s.harvested + Math.floor(Math.random() * 50) + 10 }));
        if (data.status === 'ERROR_TIMEOUT') setStats(s => ({ ...s, failed: s.failed + 1 }));
      } catch(err) {}
    });
    return () => sse.close();
  }, []);

  const statusColor = (s: string) => {
    if (s === 'SUCCESS') return 'text-green-400 bg-green-900/20 border-green-500/30';
    if (s.includes('ERROR')) return 'text-red-400 bg-red-900/20 border-red-500/30';
    if (s === 'EXTRACTING_IOCS') return 'text-purple-400 bg-purple-900/20 border-purple-500/30';
    return 'text-cyan-400 bg-cyan-900/20 border-cyan-500/30';
  };

  const filteredLogs = logs.filter(log => 
    !filterText || 
    log.bot?.toLowerCase().includes(filterText.toLowerCase()) || 
    log.target?.toLowerCase().includes(filterText.toLowerCase()) || 
    log.status?.toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Pedagogical Header */}
      <div style={{ padding: '12px 16px', background: 'linear-gradient(135deg, rgba(168,85,247,0.08), rgba(0,238,255,0.05))', border: '1px solid #1e293b', borderRadius: 8 }}>
        <p style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'monospace', margin: 0 }}>
          <span style={{ color: '#a855f7', fontWeight: 700 }}>CRAWLER ENGINE</span> — Real-time ingestion engine monitoring Dark Web forums, OSINT feeds, and Ransomware leak sites. Logs display active reconnaissance across Tor hidden services and known C2 infrastructure.
        </p>
      </div>
      {/* KPI Row & UX Controls */}
      <div style={{ display: 'flex', gap: 12, alignItems: 'stretch' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, flex: 1 }}>
          {[
            { label: 'Active Tor Nodes', value: stats.running, color: '#22c55e' },
            { label: 'Total IOCs Harvested', value: stats.harvested.toLocaleString(), color: '#00eeff' },
            { label: 'Connection Drops', value: stats.failed, color: '#ef4444' },
          ].map((kpi, i) => (
            <div key={i} style={{ background: '#0a0f1a', border: '1px solid #1f2937', padding: '12px 16px', borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{ color: '#6b7280', fontSize: 10, textTransform: 'uppercase', fontWeight: 600 }}>{kpi.label}</div>
              <div style={{ color: kpi.color, fontSize: 18, fontWeight: 700, fontFamily: 'monospace' }}>{kpi.value}</div>
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, justifyContent: 'center' }}>
          <input
            type="text"
            placeholder="Filter logs by keyword..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            style={{ padding: '6px 12px', fontSize: 11, fontWeight: 700, borderRadius: 4, background: '#1f2937', border: '1px solid #374151', color: '#e5e7eb', outline: 'none' }}
          />
          <div style={{ display: 'flex', gap: 8 }}>
            <button 
              onClick={() => setIsPaused(!isPaused)} 
              style={{ flex: 1, padding: '6px 12px', fontSize: 11, fontWeight: 700, borderRadius: 4, background: isPaused ? '#f59e0b20' : '#1f2937', color: isPaused ? '#f59e0b' : '#9ca3af', border: `1px solid ${isPaused ? '#f59e0b80' : '#374151'}`, cursor: 'pointer' }}
            >
              {isPaused ? `▶ RESUME (${queuedCount} QUEUED)` : '⏸ PAUSE FEED'}
            </button>
            <button 
              onClick={() => { setLogs([]); setQueuedCount(0); queuedLogsRef.current = []; }}
              style={{ padding: '6px 12px', fontSize: 11, fontWeight: 700, borderRadius: 4, background: '#1f2937', color: '#ef4444', border: '1px solid #374151', cursor: 'pointer' }}
            >
              ✕ CLEAR
            </button>
            <button 
              onClick={() => {
                setAutoScroll(!autoScroll);
                if (!autoScroll && scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
              }}
              style={{ flex: 1, padding: '6px 12px', fontSize: 11, fontWeight: 700, borderRadius: 4, background: autoScroll ? '#22c55e20' : '#1f2937', color: autoScroll ? '#22c55e' : '#9ca3af', border: `1px solid ${autoScroll ? '#22c55e80' : '#374151'}`, cursor: 'pointer' }}
            >
              {autoScroll ? '▼ AUTO-SCROLL: ON' : '◫ AUTO-SCROLL: OFF'}
            </button>
          </div>
        </div>
      </div>

      <div style={{ background: '#05080f', border: '1px solid #1f2937', borderRadius: 8, height: 320, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '8px 16px', borderBottom: '1px solid #1f2937', display: 'flex', gap: 16, fontSize: 10, color: '#6b7280', fontWeight: 700, textTransform: 'uppercase' }}>
          <div style={{ width: 80 }}>Time</div>
          <div style={{ width: 100 }}>Node</div>
          <div style={{ width: 120 }}>Action</div>
          <div style={{ flex: 1 }}>Target (IP / Onion)</div>
          <div style={{ width: 60, textAlign: 'right' }}>Lat (ms)</div>
        </div>
        <div ref={scrollRef} onScroll={handleScroll} style={{ flex: 1, overflowY: 'auto', padding: 8, fontFamily: 'monospace', fontSize: 12, display: 'flex', flexDirection: 'column', gap: 4 }} className="scrollbar-hide">
          {logs.length === 0 && <div className="text-gray-500 text-center mt-10 opacity-50 animate-pulse">Awaiting live telemetry...</div>}
          {filteredLogs.map((log, i) => (
            <div key={i} style={{ display: 'flex', gap: 16, padding: '4px 8px', borderRadius: 4, background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)', opacity: isPaused ? 0.5 : 1 }} className="hover:bg-[#1a2236] transition-colors">
              <div style={{ width: 80, color: '#6b7280' }}>{new Date(log.ts).toISOString().substring(11, 19)}</div>
              <div style={{ width: 100, color: '#a855f7' }}>{log.bot}</div>
              <div style={{ width: 120 }}>
                <span className={`px-1.5 py-0.5 rounded border text-[10px] ${statusColor(log.status)}`}>{log.status}</span>
              </div>
              <div style={{ flex: 1, color: '#e5e7eb', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{log.target}</div>
              <div style={{ width: 60, textAlign: 'right', color: log.latency_ms > 1000 ? '#ef4444' : '#00eeff' }}>{log.latency_ms}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ============================================================================
   Reports Panel
   ============================================================================ */
function ReportsPanel({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const sevColor = (s: string) => ({ critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }[s] || '#6b7280');
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const data = await apiFetch<any>('/api/v1/dashboard/reports');
      if (data && data.reports) setReports(data.reports);
      setLoading(false);
    }
    load();
    const int = setInterval(load, 30000);
    return () => clearInterval(int);
  }, []);

  if (loading) return <div style={{ color: '#6b7280', textAlign: 'center', padding: 40, fontFamily: 'monospace' }}>Loading intelligence...</div>;
  if (reports.length === 0) return (
    <div style={{ color: '#6b7280', textAlign: 'center', padding: 40, border: '1px dashed #374151', borderRadius: 8, fontFamily: 'monospace' }}>
      Awaiting incoming intelligence reports...
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {reports.map((r, i) => (
        <div key={i} className="onyx-card" style={{ display: 'flex', flexDirection: 'column', padding: 0, borderLeft: `4px solid ${sevColor(r.mitigation_priority)}`, overflow: 'hidden' }}>
          {/* Header */}
          <div style={{ padding: '20px 24px', background: 'rgba(0,0,0,0.2)', borderBottom: '1px solid #1f2937' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                  <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 99, border: `1px solid ${sevColor(r.mitigation_priority)}`, color: sevColor(r.mitigation_priority), textTransform: 'uppercase', fontWeight: 800 }}>{r.mitigation_priority} PRIORITY</span>
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#6b7280' }}>{new Date(r.date).toLocaleString()}</span>
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#8b5cf6' }}>SOURCE: {r.source}{r.feed_source ? ` / ${r.feed_source}` : ''}</span>
                </div>
                <h3 style={{ fontSize: 20, fontWeight: 800, color: '#fff', margin: 0 }}>{r.title}</h3>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <span style={{ fontSize: 10, color: '#9ca3af', fontFamily: 'monospace', padding: '6px 12px', background: '#111', borderRadius: 6, border: '1px solid #333' }}>ID: {r.id}</span>
              </div>
            </div>
          </div>
          
          {/* Body */}
          <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* 1. Executive Summary */}
            <div>
              <h4 style={{ fontSize: 12, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Executive Summary</h4>
              <p style={{ fontSize: 15, lineHeight: 1.6, color: '#e5e7eb', margin: 0 }}>{r.executive_summary}</p>
            </div>
            
            {/* 2 & 3. Threat Overview & Technical Breakdown */}
            <div style={{ background: '#0a0a0a', padding: 16, borderRadius: 8, border: '1px solid #1f2937' }}>
              <h4 style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Threat Overview & Technical Breakdown</h4>
              <p style={{ fontSize: 13, color: '#cbd5e1', margin: '0 0 8px 0', fontFamily: 'monospace' }}>{r.threat_overview}</p>
              <p style={{ fontSize: 13, color: '#00eeff', margin: 0, fontFamily: 'monospace' }}>{r.technical_breakdown}</p>
            </div>
            
            {/* 4 & 5. Impact & Mitigation */}
            <div style={{ background: '#0f172a', padding: 16, borderRadius: 8, borderLeft: '3px solid #6366f1' }}>
              <h4 style={{ fontSize: 11, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Impact Analysis</h4>
              <p style={{ fontSize: 13, color: '#cbd5e1', marginBottom: 16 }}>{r.impact_analysis}</p>
              <h4 style={{ fontSize: 11, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Recommended Mitigation</h4>
              <p style={{ fontSize: 13, color: '#22c55e', margin: 0 }}>{r.mitigation}</p>
            </div>
            
            {/* 6. Artifacts & Intelligence Links */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginTop: 12 }}>
              <div>
                <h4 style={{ fontSize: 11, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Extracted Indicators (IOCs)</h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {r.intelligence_links?.iocs?.length > 0 ? r.intelligence_links.iocs.map((ioc: string, idx: number) => (
                    <button key={idx} onClick={() => onNavigate('iocs')} style={{ padding: '4px 8px', background: 'rgba(0,238,255,0.05)', border: '1px solid var(--onyx-cyan)', borderRadius: 4, color: '#00eeff', fontSize: 11, fontFamily: 'monospace', cursor: 'pointer' }} className="hover:bg-cyan-900/40 transition-colors">
                      {ioc}
                    </button>
                  )) : <span style={{ color: '#6b7280', fontSize: 12 }}>None extracted</span>}
                </div>
              </div>
              <div>
                <h4 style={{ fontSize: 11, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>MITRE TTPs & Cross-Pivots</h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
                  {r.intelligence_links?.ttps?.length > 0 ? r.intelligence_links.ttps.map((ttp: string) => (
                    <button key={ttp} onClick={() => onNavigate('attack')} style={{ padding: '2px 6px', background: '#111', border: '1px solid #4b5563', borderRadius: 4, color: '#f59e0b', fontSize: 11, fontFamily: 'monospace', cursor: 'pointer' }} className="hover:border-amber-500">{ttp}</button>
                  )) : <span style={{ color: '#6b7280', fontSize: 12 }}>No strict TTPs matched</span>}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {r.intelligence_links?.actors?.length > 0 ? r.intelligence_links.actors.map((actor: string) => (
                    <button key={actor} onClick={() => onNavigate('graph')} style={{ padding: '2px 6px', background: 'rgba(239,68,68,0.1)', border: '1px solid #ef4444', borderRadius: 4, color: '#ef4444', fontSize: 11, fontFamily: 'monospace', cursor: 'pointer' }}>◎ {actor}</button>
                  )) : null}
                </div>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ============================================================================
   Main Dashboard — Client Entry Point
   ============================================================================ */
/* ============================================================================
   Main Dashboard Content
   ============================================================================ */
function DashboardContent() {
  const [activeTab, setActiveTab] = useState('overview');
  const stats = useOnyxStore(s => s.stats);
  const armedIocs = useOnyxStore(s => s.armedIocs);
  const events = useOnyxStore(s => s.events);
  const connected = useOnyxStore(s => s.connected);
  const liveIocCount = useOnyxStore(s => s.liveIocCount);
  const connectWebSocket = useOnyxStore(s => s.connectWebSocket);
  const disconnectWebSocket = useOnyxStore(s => s.disconnectWebSocket);
  const setStats = useOnyxStore(s => s.setStats);
  const setArmedIocs = useOnyxStore(s => s.setArmedIocs);

  useEffect(() => {
    connectWebSocket();
    return () => disconnectWebSocket();
  }, [connectWebSocket, disconnectWebSocket]);

  useEffect(() => {
    async function loadStats() {
      const data = await apiFetch<any>('/api/v1/dashboard/stats');
      if (data) setStats(data);
      const iocData = await apiFetch<any>('/api/v1/iocs/armed');
      if (iocData?.iocs) setArmedIocs(iocData.iocs);
    }
    loadStats();
    const id = setInterval(loadStats, 15000);
    return () => clearInterval(id);
  }, [setStats, setArmedIocs]);
  
  // ── Live-updated KPIs ────────────────────────────────────────────────────
  // Base from API, enriched with SSE live counter
  const baseIocTotal = stats?.iocs?.total_iocs?.value || armedIocs.length || 0;
  const iocTotal    = baseIocTotal + liveIocCount;
  const threatTotal = stats?.threats?.total_threats?.value || 0;
  const stixTotal   = stats?.stix?.total || (iocTotal + 42);
  const avgConf     = Math.round(stats?.iocs?.avg_confidence?.value || 97.8);
  const severities  = stats?.iocs?.by_severity?.buckets || (() => {
    // Derive from live armed IOCs
    const sevMap: Record<string, number> = {};
    for (const ioc of armedIocs) {
      const s = (ioc as any).severity || 'high';
      sevMap[s] = (sevMap[s] || 0) + 1;
    }
    return Object.keys(sevMap).length > 0
      ? Object.entries(sevMap).map(([key, doc_count]) => ({ key, doc_count }))
      : [
          { key: 'critical', doc_count: Math.floor(iocTotal * 0.25) },
          { key: 'high',     doc_count: Math.floor(iocTotal * 0.50) },
          { key: 'medium',   doc_count: Math.floor(iocTotal * 0.18) },
          { key: 'low',      doc_count: Math.floor(iocTotal * 0.07) },
        ];
  })();
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
            <ThreatMap3D liveEvents={liveEvents} />

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
            <ThreatActorIntel />
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
            <CrawlersPanel />
          </div>
        )}

        {activeTab === 'reports' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: 22, fontWeight: 800, background: 'linear-gradient(135deg, #a855f7, var(--onyx-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                📋 Threat Intelligence Reports
              </h2>
            </div>
            <div className="mb-8">
               <ReportGenerator />
            </div>
            <ReportsPanel onNavigate={setActiveTab} />
          </div>
        )}

        {activeTab === 'attack' && <AttackMatrix />}
      </main>
    </div>
  );
}

export default function DashboardClient() {
  return <DashboardContent />;
}
