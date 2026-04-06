'use client';

import { useEffect, useState, useCallback } from 'react';
import ThreatGraph from '@/components/ThreatGraph';
import AttackMatrix from '@/components/AttackMatrix';

/* ============================================================================
   Type Definitions
   ============================================================================ */
interface DashboardStats {
  iocs: { total_iocs?: { value: number }; by_type?: { buckets: Array<{ key: string; doc_count: number }> }; by_severity?: { buckets: Array<{ key: string; doc_count: number }> }; timeline_24h?: { buckets: Array<{ key_as_string: string; doc_count: number }> }; avg_confidence?: { value: number } };
  threats: { total_threats?: { value: number }; by_type?: { buckets: Array<{ key: string; doc_count: number }> } };
  stix: { types: Record<string, number>; total: number };
  crawlers: Array<{ crawler_id: string; status: string; last_run?: string }>;
}

interface SSEEvent {
  type: string;
  data: Record<string, unknown>;
  timestamp: string;
}

/* ============================================================================
   API Client
   ============================================================================ */
const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

async function fetchStats(): Promise<DashboardStats | null> {
  try {
    const res = await fetch(`${API}/api/v1/dashboard/stats`);
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
          setEvents((prev) => [{ type: e.type || 'message', data, timestamp: new Date().toISOString() }, ...prev.slice(0, 99)]);
        } catch {}
      };
      es.onerror = () => { setConnected(false); es?.close(); };
    } catch {}
    return () => { es?.close(); };
  }, [url]);

  return { events, connected };
}

/* ============================================================================
   Components
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

function Sidebar({ activeTab, onTabChange }: { activeTab: string; onTabChange: (t: string) => void }) {
  const navItems = [
    { id: 'overview', icon: '◈', label: 'Overview' },
    { id: 'iocs', icon: '⬡', label: 'IOC Explorer' },
    { id: 'threats', icon: '☠', label: 'Threat Actors' },
    { id: 'graph', icon: '◎', label: 'Threat Graph' },
    { id: 'crawlers', icon: '🕸', label: 'Crawlers' },
    { id: 'reports', icon: '📋', label: 'Reports' },
    { id: 'attack', icon: '⚔', label: 'ATT&CK Matrix' },
  ];

  return (
    <aside className="onyx-sidebar">
      <Logo />
      <nav style={{ flex: 1 }}>
        {navItems.map((item) => (
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
          {new Date().toLocaleTimeString('en-US', { hour12: false })} UTC
        </span>
      </div>
    </header>
  );
}

function StatCard({ label, value, trend, icon }: { label: string; value: string | number; trend?: string; icon: string }) {
  return (
    <div className="onyx-card stat-widget animate-in">
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

function LiveFeed({ events }: { events: SSEEvent[] }) {
  return (
    <div className="onyx-card span-2 row-2 animate-in" style={{ animationDelay: '0.5s' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-md)' }}>
        <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
          <span className="pulse-live" /> Live Event Feed
        </h3>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)' }}>{events.length} events</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)', maxHeight: '400px', overflowY: 'auto' }}>
        {events.length === 0 && <div style={{ textAlign: 'center', padding: 'var(--space-xl)', color: 'var(--text-tertiary)', fontSize: 'var(--font-size-sm)' }}>Waiting for events... Connect the API to see real-time data.</div>}
        {events.map((ev, i) => (
          <div key={i} className="animate-in" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-md)', padding: 'var(--space-sm) var(--space-md)', background: 'var(--onyx-bg-tertiary)', borderRadius: 'var(--radius-sm)', borderLeft: `3px solid ${ev.data?.severity === 'critical' ? 'var(--severity-critical)' : ev.data?.severity === 'high' ? 'var(--severity-high)' : 'var(--onyx-cyan)'}` }}>
            <span style={{ fontSize: 'var(--font-size-xs)', fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)', whiteSpace: 'nowrap' }}>
              {new Date(ev.timestamp).toLocaleTimeString('en-US', { hour12: false })}
            </span>
            <span className="ioc-value" style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {String(ev.data?.value || ev.data?.ioc_id || ev.type || 'event')}
            </span>
            <IOCTypeBadge type={String(ev.data?.type || 'info')} />
          </div>
        ))}
      </div>
    </div>
  );
}

function SeverityChart({ data }: { data?: Array<{ key: string; doc_count: number }> }) {
  const severities = data || [];
  const total = severities.reduce((s, d) => s + d.doc_count, 0) || 1;
  const colors: Record<string, string> = { critical: 'var(--severity-critical)', high: 'var(--severity-high)', medium: 'var(--severity-medium)', low: 'var(--severity-low)', info: 'var(--severity-info)' };

  return (
    <div className="onyx-card animate-in" style={{ animationDelay: '0.3s' }}>
      <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, marginBottom: 'var(--space-md)' }}>Severity Distribution</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)' }}>
        {severities.map((s) => (
          <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-md)' }}>
            <span style={{ fontSize: 'var(--font-size-xs)', fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)', width: '60px', textTransform: 'uppercase' }}>{s.key}</span>
            <div style={{ flex: 1, height: '8px', background: 'var(--onyx-bg-primary)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
              <div style={{ width: `${(s.doc_count / total) * 100}%`, height: '100%', background: colors[s.key] || 'var(--text-tertiary)', borderRadius: 'var(--radius-full)', transition: 'width 1s ease-out' }} />
            </div>
            <span style={{ fontSize: 'var(--font-size-xs)', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', width: '40px', textAlign: 'right' }}>{s.doc_count}</span>
          </div>
        ))}
        {severities.length === 0 && <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-tertiary)', textAlign: 'center', padding: 'var(--space-lg)' }}>No data yet</div>}
      </div>
    </div>
  );
}

function CrawlerStatus({ crawlers }: { crawlers?: Array<{ crawler_id: string; status: string; last_run?: string }> }) {
  const statusColors: Record<string, string> = { running: 'var(--onyx-green)', idle: 'var(--onyx-cyan)', error: 'var(--onyx-red)', stopped: 'var(--text-tertiary)' };

  return (
    <div className="onyx-card animate-in" style={{ animationDelay: '0.4s' }}>
      <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, marginBottom: 'var(--space-md)' }}>🕸 Crawler Status</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)' }}>
        {(!crawlers || crawlers.length === 0) && (
          <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-tertiary)', textAlign: 'center', padding: 'var(--space-lg)' }}>No crawlers configured</div>
        )}
        {crawlers?.map((c) => (
          <div key={c.crawler_id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 'var(--space-sm)', background: 'var(--onyx-bg-tertiary)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: statusColors[c.status] || 'var(--text-tertiary)' }} />
              <span style={{ fontSize: 'var(--font-size-sm)', fontFamily: 'var(--font-mono)' }}>{c.crawler_id}</span>
            </div>
            <span style={{ fontSize: 'var(--font-size-xs)', color: statusColors[c.status], fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{c.status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============================================================================
   Main Dashboard Page
   ============================================================================ */
export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const { events, connected } = useSSE(`${API}/api/v1/dashboard/events/stream`);

  const loadStats = useCallback(async () => {
    const data = await fetchStats();
    if (data) setStats(data);
    setLoading(false);
  }, []);

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, [loadStats]);

  const iocTotal = stats?.iocs?.total_iocs?.value || 0;
  const threatTotal = stats?.threats?.total_threats?.value || 0;
  const stixTotal = stats?.stix?.total || 0;
  const avgConf = Math.round(stats?.iocs?.avg_confidence?.value || 0);

  return (
    <div className="onyx-layout">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />
      <Header connected={connected} />
      <main className="onyx-main">
        {activeTab === 'overview' && (
          <div className="widget-grid">
            {/* KPI Row */}
            <StatCard label="Total IOCs" value={iocTotal} trend="+12% 24h" icon="⬡" />
            <StatCard label="Threat Entities" value={threatTotal} trend="+3 new" icon="☠" />
            <StatCard label="STIX Objects" value={stixTotal} icon="◎" />
            <StatCard label="Avg Confidence" value={`${avgConf}%`} icon="◈" />

            {/* Charts + Live Feed */}
            <SeverityChart data={stats?.iocs?.by_severity?.buckets} />
            <CrawlerStatus crawlers={stats?.crawlers} />
            <LiveFeed events={events} />
          </div>
        )}

        {activeTab === 'graph' && <ThreatGraph />}
        
        {activeTab === 'attack' && <AttackMatrix />}

        {activeTab !== 'overview' && activeTab !== 'graph' && activeTab !== 'attack' && (
          <div className="onyx-card animate-in" style={{ textAlign: 'center', padding: 'var(--space-3xl)' }}>
            <h2 style={{ fontSize: 'var(--font-size-2xl)', fontWeight: 800, marginBottom: 'var(--space-md)', background: 'linear-gradient(135deg, var(--onyx-cyan), var(--onyx-magenta))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              {activeTab.charAt(0).toUpperCase() + activeTab.slice(1)}
            </h2>
            <p style={{ color: 'var(--text-secondary)' }}>Module loading — connect the API to activate this view.</p>
          </div>
        )}
      </main>
    </div>
  );
}
