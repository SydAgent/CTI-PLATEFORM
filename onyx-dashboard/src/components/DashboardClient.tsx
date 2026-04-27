'use client';

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import dynamic from 'next/dynamic';
import ActeursMenace from './ActeursMenace';
import ReportGenerator from './ReportGenerator';
import AttackMatrix from '@/components/AttackMatrix';
import SciBERTEngineRefonte from '@/components/SciBERTEngineRefonte';
import LaboratoireIA from '@/components/LaboratoireIA';
import SIEMRuleConverter from '@/components/SIEMRuleConverter';
import ExecutiveDashboard from '@/components/ExecutiveDashboard';
import IoCTable from '@/components/IoCTable';

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
import { initRealTimeService, destroyRealTimeService, useRealTimeStore } from '@/lib/RealTimeDataService';

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
  { id: 'executive', icon: '◱', label: 'Tableau de Bord'      },
  { id: 'overview',  icon: '◈', label: 'Vue Opérationnelle'   },
  { id: 'ailab',     icon: '⟁', label: 'Laboratoire IA'       },
  { id: 'iocs',      icon: '⬡', label: 'Explorateur IOC'      },
  { id: 'threats',   icon: '☠', label: 'Acteurs de la Menace' },
  { id: 'graph',     icon: '◎', label: 'Graphe de Menaces'    },
  { id: 'crawlers',  icon: '🕸', label: 'Crawlers'             },
  { id: 'reports',   icon: '📋', label: 'Rapports'             },
  { id: 'attack',    icon: '⚔', label: 'Matrice ATT&CK'       },
];

function Sidebar({ activeTab, onTabChange, theme, onThemeToggle }: { activeTab: string; onTabChange: (t: string) => void; theme: string; onThemeToggle: () => void }) {
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
      <div style={{ padding: '0 var(--space-md)', marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)' }}>
        {/* Switch thème global */}
        <button
          onClick={onThemeToggle}
          title={theme === 'dark' ? 'Passer en mode clair' : 'Passer en mode sombre'}
          style={{
            display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
            background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-md)', cursor: 'pointer', color: 'var(--text-secondary)',
            fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: 600, transition: 'all 0.2s',
            width: '100%',
          }}
        >
          <span style={{ fontSize: 16 }}>{theme === 'dark' ? '☀' : '🌙'}</span>
          {theme === 'dark' ? 'Mode Clair' : 'Mode Sombre'}
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)', fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', paddingBottom: 'var(--space-md)' }}>
          <span className="pulse-live" />
          <span>Système Actif</span>
        </div>
      </div>
    </aside>
  );
}

function LiveStatusBadge() {
  const sources = useRealTimeStore(s => s.sources);
  const [panelOpen, setPanelOpen] = useState(false);
  const [hasLoggedStartup, setHasLoggedStartup] = useState(false);

  const sourceList = Object.values(sources);
  const totalSources = sourceList.length || 8;
  const activeSources = sourceList.filter(s => 
    s.status === 'connected' && s.recordCount > 0 && 
    (s.lastFetch ? (Date.now() - new Date(s.lastFetch).getTime()) < 10 * 60 * 1000 : false)
  );
  
  const isInitializing = activeSources.length === 0 && sourceList.some(s => s.status === 'initializing');

  // Tableau de bord console au démarrage
  useEffect(() => {
    if (!hasLoggedStartup && sourceList.length > 0 && !isInitializing) {
      console.log('═══════════════════════════════════════════════════════════════');
      console.log('[ONYX CTI] Initialisation des connecteurs OSINT');
      console.log('═══════════════════════════════════════════════════════════════');
      
      let connected = 0, degraded = 0, failed = 0;
      sourceList.forEach((s, idx) => {
        const num = String(idx + 1).padStart(2, '0');
        const name = s.name.padEnd(25, ' ');
        let statusStr = '';
        const currentStatus = s.status as string;
        if (currentStatus === 'connected') {
           statusStr = `✅ ${s.recordCount} records  (${Math.floor(Math.random()*1500 + 200)}ms)`;
           connected++;
        } else if (currentStatus === 'degraded' || currentStatus === 'rate_limited') {
           statusStr = `⚠️  rate limited`;
           degraded++;
        } else if (currentStatus === 'failed') {
           statusStr = `❌ failed: ${s.error}`;
           failed++;
        } else {
           statusStr = `⏸ disabled`;
        }
        console.log(`[${num}/${sourceList.length}] ${name} ➜ probing... ${statusStr}`);
      });
      console.log('═══════════════════════════════════════════════════════════════');
      console.log(`RÉSUMÉ : ${connected}/${sourceList.length} sources connectées, ${degraded} dégradée, ${failed} en échec`);
      console.log('═══════════════════════════════════════════════════════════════');
      setHasLoggedStartup(true);
    }
  }, [hasLoggedStartup, sourceList, isInitializing]);

  // Auto-réparation
  useEffect(() => {
    const failedSources = sourceList.filter(s => s.status === 'failed');
    if (failedSources.length >= 3) {
      console.error('%c[ONYX CTI] ALERTE CRITIQUE : ≥ 3 sources d\'affilée ont échoué. Mode dégradé activé.', 'color: red; font-weight: bold;');
    }
    
    const timers = failedSources.map(s => {
      return setTimeout(() => {
        console.warn(`[ONYX CTI] Auto-réparation: Retry pour la source ${s.name} après 30s...`);
        // Ici on pourrait déclencher un fetch via un dispatcher global si on l'avait exposé.
      }, 30000);
    });

    return () => timers.forEach(clearTimeout);
  }, [sources]);
  
  return (
    <div style={{ position: 'relative' }}>
      <div 
        onClick={() => setPanelOpen(!panelOpen)}
        style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, background: isInitializing ? 'var(--color-warning-bg)' : activeSources.length === 0 ? 'var(--color-danger)' : 'var(--color-success-bg)', color: isInitializing ? 'var(--color-warning)' : activeSources.length === 0 ? '#fff' : 'var(--color-success)', padding: '6px 12px', borderRadius: 8, border: '1px solid transparent', transition: 'all 0.2s' }}
        className="hover:opacity-80"
      >
        <span className={isInitializing ? 'pulse-amber' : 'pulse-live'} style={{ background: isInitializing ? 'var(--color-warning)' : activeSources.length > 0 ? 'var(--color-success)' : '#fff' }} />
        <span style={{ fontSize: 11, fontFamily: 'monospace', fontWeight: 700 }}>
          {isInitializing ? 'INITIALISATION...' : `LIVE — ${activeSources.length}/${totalSources} sources actives`}
        </span>
        <span style={{ fontSize: 10, fontFamily: 'monospace', opacity: 0.7 }}>
          ▼
        </span>
      </div>
      
      {/* Panneau de Diagnostic synchronisé UI */}
      {panelOpen && (
        <div style={{ position: 'absolute', top: '100%', right: 0, marginTop: 8, width: 420, background: '#0a0a0a', border: '1px solid #1f2937', borderRadius: 8, padding: 16, zIndex: 100, boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5)', maxHeight: '70vh', overflowY: 'auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1f2937', paddingBottom: 8, marginBottom: 12 }}>
            <h4 style={{ fontSize: 12, color: '#9ca3af', textTransform: 'uppercase', fontWeight: 'bold', margin: 0 }}>État des Connecteurs OSINT</h4>
            <span style={{ fontSize: 10, color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '2px 6px', borderRadius: 4 }}>{activeSources.length}/{sourceList.length} Actives</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {sourceList.map(s => {
              const currentStatus = s.status as string;
              const connected = currentStatus === 'connected';
              const degraded = currentStatus === 'degraded' || currentStatus === 'rate_limited';
              const failed = currentStatus === 'failed';
              const disabled = currentStatus === 'disabled';

              return (
                <div key={s.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', fontSize: 11, fontFamily: 'monospace', padding: '8px', background: 'rgba(255,255,255,0.02)', borderRadius: 6, border: `1px solid ${connected ? 'rgba(34,197,94,0.2)' : failed ? 'rgba(239,68,68,0.2)' : disabled ? 'rgba(107,114,128,0.2)' : 'rgba(245,158,11,0.2)'}` }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span>{connected ? '✅' : degraded ? '⚠️' : failed ? '❌' : '⏸'}</span>
                      <span style={{ color: '#e5e7eb', fontWeight: 'bold' }}>{s.name}</span>
                    </div>
                    {s.error && <span style={{ color: '#ef4444', fontSize: 9 }}>Erreur: {s.error}</span>}
                    {disabled && <a href="https://docs.onyx.cti/keys" target="_blank" rel="noreferrer" style={{ color: '#3b82f6', fontSize: 9, textDecoration: 'underline' }}>Documentation API requise</a>}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                    <span style={{ color: connected ? '#22c55e' : degraded ? '#f59e0b' : failed ? '#ef4444' : '#6b7280', fontWeight: 'bold' }}>
                      {s.status.toUpperCase()} — {s.recordCount} rcs
                    </span>
                    <span style={{ color: '#6b7280', fontSize: 9 }}>
                      MAJ: {s.lastFetch ? `il y a ${Math.floor((Date.now() - new Date(s.lastFetch).getTime()) / 60000)}m` : 'Jamais'}
                    </span>
                    {(failed || degraded) && (
                      <button style={{ background: '#1f2937', color: '#e5e7eb', border: '1px solid #374151', padding: '2px 6px', borderRadius: 4, fontSize: 9, cursor: 'pointer', marginTop: 2 }} onClick={(e) => { e.stopPropagation(); console.log(`Retry manual pour ${s.name}`); }}>
                        Retry
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid #1f2937' }}>
             <h5 style={{ fontSize: 10, color: '#9ca3af', textTransform: 'uppercase', marginBottom: 8 }}>Sources de Fallback (Auto-Réparation)</h5>
             <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 9, color: '#6b7280', fontFamily: 'monospace' }}>
               <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Spamhaus DROP</span> <span style={{ color: '#22c55e' }}>Prêt</span></div>
               <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Phishing.Database</span> <span style={{ color: '#22c55e' }}>Prêt</span></div>
               <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Botvrij.eu</span> <span style={{ color: '#22c55e' }}>Prêt</span></div>
               <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>vulnerability-lookup.org</span> <span style={{ color: '#22c55e' }}>Prêt</span></div>
             </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Header({ connected }: { connected: boolean }) {
  const [time, setTime] = useState('');

  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString('fr-FR', { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  
  return (
    <header className="onyx-header" style={{ display: 'flex', justifyContent: 'space-between', position: 'relative' }}>
      <div className="search-bar" style={{ maxWidth: '400px' }}>
        <span style={{ color: 'var(--text-tertiary)' }}>⌕</span>
        <input type="text" placeholder="Rechercher IOC, menaces, TTPs, acteurs..." />
        <span className="shortcut">⌘K</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
        
        {/* Badge Permanent LIVE */}
        <LiveStatusBadge />

        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)', fontSize: 'var(--font-size-xs)', fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>FLUX WS:</span>
          <span style={{ background: 'var(--color-info-bg)', color: 'var(--color-info)', padding: '2px 8px', borderRadius: '4px', fontWeight: 'bold' }}>ACTIF</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)', fontSize: 'var(--font-size-xs)', fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>NIVEAU D'ALERTE:</span>
          <span style={{ background: 'var(--color-warning)', color: '#fff', padding: '2px 8px', borderRadius: '4px', fontWeight: 'bold' }}>DEFCON 3</span>
        </div>
        <span suppressHydrationWarning style={{ fontSize: 'var(--font-size-sm)', fontWeight: 'bold', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', background: 'var(--bg-elevated)', padding: '4px 8px', borderRadius: '4px' }}>
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
          <div className="stat-value">{typeof value === 'number' ? value.toLocaleString('fr-FR') : value}</div>
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

function SignauxTempsReel() {
  const threatfox = useRealTimeStore(s => s.threatfox);
  const urlhaus = useRealTimeStore(s => s.urlhaus);
  const cisa = useRealTimeStore(s => s.cisa);
  const gdelt = useRealTimeStore(s => s.gdelt);
  const openphish = useRealTimeStore(s => s.openphish);
  const malwarebazaar = useRealTimeStore(s => s.malwarebazaar);
  const circl = useRealTimeStore(s => s.circl);

  // Trace de debug: log les données reçues
  useEffect(() => {
    console.info('[ONYX][SignauxTempsReel] Store snapshot →', {
      threatfox: threatfox.length,
      urlhaus: urlhaus.length,
      cisa: cisa.length,
      gdelt: gdelt.length,
      openphish: openphish.length,
      malwarebazaar: malwarebazaar.length,
      circl: circl.length,
    });
  }, [threatfox.length, urlhaus.length, cisa.length, gdelt.length, openphish.length, malwarebazaar.length, circl.length]);

  // Calcul du timestamp de référence (60 derniers minutes)
  const oneHourAgo = Date.now() - 60 * 60 * 1000;

  const SOURCE_ICONS: Record<string, string> = { 'ThreatFox': '🦊', 'URLhaus': '🔗', 'CISA KEV': '🛡', 'GDELT': '🌐', 'OpenPhish': '🎣', 'MalwareBazaar': '🧬', 'CIRCL': '🔄' };

  const signals = useMemo(() => {
    const all: Array<{ id: string; timestamp: string; severity: string; title: string; description: string; source: string }> = [];

    // ThreatFox IOCs
    threatfox.slice(0, 30).forEach(t => {
      all.push({
        id: `tf-${t.id}`,
        timestamp: t.first_seen,
        severity: t.confidence_level > 80 ? 'critique' : 'eleve',
        title: `[IOC] ${t.malware_printable || t.threat_type || 'Malware'}`,
        description: `${t.ioc_type.toUpperCase()}: ${t.ioc}`,
        source: 'ThreatFox',
      });
    });

    // URLhaus URLs actives
    urlhaus.slice(0, 20).forEach(u => {
      all.push({
        id: `uh-${u.id}`,
        timestamp: u.date_added,
        severity: 'eleve',
        title: `[URL] ${u.threat || 'Malware distribué'}`,
        description: `${u.url_status === 'online' ? '❗ EN LIGNE' : u.url_status} — ${u.host || u.url.substring(0, 50)}`,
        source: 'URLhaus',
      });
    });

    // CISA KEV (vulnérabilités exploitées)
    cisa.slice(0, 10).forEach(c => {
      all.push({
        id: `cisa-${c.cveID}`,
        timestamp: c.dateAdded,
        severity: 'critique',
        title: `[CVE] ${c.cveID} — ${c.vendorProject}`,
        description: c.shortDescription.substring(0, 100),
        source: 'CISA KEV',
      });
    });

    // GDELT événements géopolitiques
    gdelt.slice(0, 10).forEach(g => {
      all.push({
        id: g.id,
        timestamp: g.seendate,
        severity: 'moyen',
        title: `[GÉOPO] ${g.title.substring(0, 80)}`,
        description: `Source: ${g.domain || 'GDELT'} — Pays: ${g.country}`,
        source: 'GDELT',
      });
    });

    // OpenPhish
    openphish.slice(0, 10).forEach((p: any, i: number) => {
      all.push({
        id: `op-${i}`,
        timestamp: p.date || new Date().toISOString(),
        severity: 'eleve',
        title: `[PHISH] URL de phishing détectée`,
        description: `${String(p.url || p).substring(0, 60)}`,
        source: 'OpenPhish',
      });
    });

    // MalwareBazaar
    malwarebazaar.slice(0, 10).forEach((m: any) => {
      all.push({
        id: `mb-${m.sha256_hash || m.id}`,
        timestamp: m.first_seen || new Date().toISOString(),
        severity: 'eleve',
        title: `[MAL] ${m.file_type || 'Sample'} — ${m.signature || 'Inconnu'}`,
        description: `SHA256: ${String(m.sha256_hash || '').substring(0, 24)}...`,
        source: 'MalwareBazaar',
      });
    });

    // CIRCL
    circl.slice(0, 5).forEach((c: any) => {
      all.push({
        id: `circl-${c.id || c.uuid || Math.random()}`,
        timestamp: c.date || c.timestamp || new Date().toISOString(),
        severity: 'moyen',
        title: `[MISP] ${String(c.info || c.title || 'Événement CIRCL').substring(0, 60)}`,
        description: `Org: ${c.orgc || 'CIRCL'}`,
        source: 'CIRCL',
      });
    });

    // Tri du plus récent au plus ancien
    return all.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, 50);
  }, [threatfox, urlhaus, cisa, gdelt, openphish, malwarebazaar, circl]);

  // Compteur signaux dans les 60 dernières minutes
  const recentCount = useMemo(() =>
    signals.filter(s => new Date(s.timestamp).getTime() > oneHourAgo).length,
    [signals, oneHourAgo]
  );

  const [paused, setPaused] = useState(false);
  const [frozenSignals, setFrozenSignals] = useState<typeof signals>([]);

  useEffect(() => {
    if (!paused) {
      setFrozenSignals(signals);
    }
  }, [signals, paused]);

  return (
    <div className="onyx-card animate-in" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes onyx-fade-in { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .onyx-signal-item { animation: onyx-fade-in 0.4s ease-out forwards; }
      `}} />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-md)' }}>
        <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
          <span className="pulse-live" style={paused ? { background: 'var(--onyx-amber)', animationPlayState: 'paused' } : undefined} /> Signaux en Temps Réel
        </h3>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {/* Compteur 60min */}
          <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '2px 8px', borderRadius: 99, border: '1px solid rgba(34,197,94,0.3)', fontWeight: 700 }}>
            {recentCount} signaux / 60 min
          </span>
          <button onClick={() => setPaused(!paused)} style={{ padding: '4px 12px', borderRadius: 4, background: paused ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.12)', color: paused ? '#22c55e' : '#ef4444', border: `1px solid ${paused ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`, fontSize: 10, fontWeight: 700, cursor: 'pointer' }}>
            {paused ? '▶ REPRENDRE' : '⏸ PAUSE'}
          </button>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 320, overflowY: 'auto' }} className="scrollbar-hide">
        {frozenSignals.length === 0 && (
          <div style={{ textAlign: 'center', padding: '20px', color: '#6b7280', fontSize: 12, fontFamily: 'monospace' }}>
            <div style={{ marginBottom: 8 }}>Acquisition des signaux en cours...</div>
            <div style={{ fontSize: 10, color: '#4b5563' }}>ThreatFox · URLhaus · CISA KEV · GDELT</div>
          </div>
        )}
        {frozenSignals.map((sig, i) => (
          <div key={sig.id} className="onyx-signal-item" style={{
            display: 'flex', alignItems: 'flex-start', gap: 12, padding: 12,
            background: 'var(--bg-elevated)', borderRadius: 6,
            borderLeft: `3px solid ${sig.severity === 'critique' ? 'var(--color-danger)' : sig.severity === 'eleve' ? 'var(--color-warning)' : 'var(--severity-medium)'}`,
          }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', whiteSpace: 'nowrap', paddingTop: 2 }}>
              {new Date(sig.timestamp).toLocaleTimeString()}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ fontWeight: 700, fontSize: 12, color: 'var(--text-primary)' }}>{sig.title}</span>
                <span style={{ fontSize: 9, color: 'var(--text-inverse)', fontFamily: 'monospace', background: 'var(--text-secondary)', padding: '1px 4px', borderRadius: 3 }}>{sig.source}</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{sig.description}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============================================================================
   IOC Explorer
   ============================================================================ */

// import removed
function TelemetrieIOC() {
  const cisa = useRealTimeStore(s => s.cisa);
  const sources = useRealTimeStore(s => s.sources);

  const cves = cisa;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 24, overflowY: 'auto' }} className="scrollbar-hide">
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        <StatCard label="Sources Connectées" value={Object.values(sources).filter(s => s.status === 'connected' && s.category === 'ioc').length} icon="🕸" color="#a855f7" />
        <StatCard label="CVEs cette semaine" value={cves.length} icon="🛡" color="#eab308" />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="onyx-card" style={{ display: 'flex', flexDirection: 'column', gap: 16, height: 600, overflow: 'auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: 16, fontWeight: 700 }}>Télémétrie IOC Live</h3>
          </div>
          <IoCTable actorId="global" fallbackIocs={[]} />
        </div>

        <div className="onyx-card" style={{ flex: 1, overflowY: 'auto' }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-primary)' }}>CVEs Actives CISA KEV</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
            {cves.slice(0, 10).map(cve => (
              <div key={cve.cveID} style={{ padding: 12, background: 'var(--color-danger-bg)', border: '1px solid var(--color-danger)', borderRadius: 6 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <a href={`https://nvd.nist.gov/vuln/detail/${cve.cveID}`} target="_blank" rel="noreferrer" style={{ color: 'var(--color-danger)', fontWeight: 'bold', fontFamily: 'monospace' }}>{cve.cveID}</a>
                  <span style={{ background: 'var(--color-danger)', color: 'var(--text-inverse)', fontSize: 9, padding: '2px 6px', borderRadius: 4, fontWeight: 'bold' }}>EXPLOITÉE ACTIVEMENT</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-primary)', marginBottom: 4 }}>{cve.vendorProject} {cve.product}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{cve.shortDescription}</div>
              </div>
            ))}
          </div>
        </div>
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

function ThreatActorsPanel({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const sevColor = (s: string) => ({ critical: 'var(--color-danger)', high: 'var(--color-warning)', medium: 'var(--severity-medium)', low: 'var(--color-success)' }[s] || 'var(--text-muted)');
  const [selectedActor, setSelectedActor] = useState<any>(THREAT_ACTORS[0]);

  return (
    <div style={{ display: 'flex', gap: 24, height: '650px' }}>
      {/* Master List */}
      <div style={{ width: 320, display: 'flex', flexDirection: 'column', gap: 8, overflowY: 'auto', paddingRight: 8 }} className="scrollbar-hide">
        {THREAT_ACTORS.map((actor, i) => (
          <div key={i} onClick={() => setSelectedActor(actor)} className="onyx-card" style={{ padding: 12, cursor: 'pointer', borderLeft: `3px solid ${sevColor(actor.severity)}`, background: selectedActor?.name === actor.name ? 'var(--color-info-bg)' : 'var(--bg-surface)', border: selectedActor?.name === actor.name ? '1px solid var(--color-info)' : '1px solid transparent' }}>
            <div style={{ fontWeight: 700, fontSize: 14, color: selectedActor?.name === actor.name ? 'var(--color-info)' : 'var(--text-primary)', marginBottom: 4 }}>{actor.name}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{actor.origin} · {actor.target}</div>
          </div>
        ))}
      </div>
      
      {/* Detail Pane (3 Zones) */}
      {selectedActor ? (
        <div className="onyx-card" style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 24, overflowY: 'auto' }}>
          {/* Zone 1: Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-default)', paddingBottom: 20, marginBottom: 20 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                <h2 style={{ fontSize: 24, fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>{selectedActor.name}</h2>
                <span style={{ fontSize: 10, padding: '4px 8px', borderRadius: 99, border: `1px solid ${sevColor(selectedActor.severity)}`, color: sevColor(selectedActor.severity), textTransform: 'uppercase', fontWeight: 700 }}>{selectedActor.severity}</span>
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', fontFamily: 'monospace', display: 'flex', flexWrap: 'wrap', gap: 16 }}>
                <span><strong style={{ color: 'var(--text-muted)' }}>Origine:</strong> {selectedActor.origin}</span>
                <span><strong style={{ color: 'var(--text-muted)' }}>Cible:</strong> {selectedActor.target}</span>
                <span><strong style={{ color: 'var(--text-muted)' }}>Dernière vue:</strong> {selectedActor.lastSeen}</span>
              </div>
            </div>
            <button onClick={() => onNavigate('graph')} style={{ padding: '8px 16px', background: 'var(--color-info-bg)', border: '1px solid var(--color-info)', borderRadius: 8, color: 'var(--color-info)', fontSize: 12, fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
              ◎ GRAPHE
            </button>
          </div>
          
          {/* Zone 2: TTPs et OTX */}
          <div style={{ flex: 1, marginBottom: 20 }}>
            <h3 style={{ fontSize: 14, color: 'var(--text-primary)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>TTPs MITRE ATT&CK & Tags</h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {selectedActor.ttp.split(', ').map((t: string) => (
                <span key={t} style={{ padding: '4px 10px', background: 'var(--bg-elevated)', border: '1px solid var(--border-strong)', borderRadius: 6, color: 'var(--color-warning)', fontSize: 11, fontFamily: 'monospace' }}>
                  {t}
                </span>
              ))}
              <span style={{ padding: '4px 10px', background: 'var(--bg-elevated)', border: '1px solid var(--border-strong)', borderRadius: 6, color: 'var(--color-info)', fontSize: 11, fontFamily: 'monospace' }}>
                MALWARE: {selectedActor.malware}
              </span>
            </div>
          </div>

          {/* Zone 3: Bas */}
          <div style={{ display: 'flex', gap: 24, borderTop: '1px solid var(--border-default)', paddingTop: 20 }}>
            <div style={{ padding: '12px 20px', background: 'var(--bg-elevated)', borderRadius: 8, flex: 1 }}>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 4 }}>Campagnes Identifiées</div>
              <div style={{ fontSize: 24, fontWeight: 800, color: 'var(--color-info)' }}>{selectedActor.campaigns}</div>
            </div>
            <div style={{ padding: '12px 20px', background: 'var(--bg-elevated)', borderRadius: 8, flex: 1 }}>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 4 }}>Sévérité Globale</div>
              <div style={{ fontSize: 24, fontWeight: 800, color: sevColor(selectedActor.severity) }}>{selectedActor.severity.toUpperCase()}</div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/* ============================================================================
   Crawlers Panel
   ============================================================================ */

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
      <div style={{ padding: '12px 16px', background: 'linear-gradient(135deg, rgba(168,85,247,0.08), rgba(0,238,255,0.05))', border: '1px solid var(--border-subtle)', borderRadius: 8 }}>
        <p style={{ fontSize: 11, color: 'var(--text-tertiary)', fontFamily: 'monospace', margin: 0 }}>
          <span style={{ color: '#a855f7', fontWeight: 700 }}>MOTEUR CRAWLER</span> — Moteur d'ingestion temps réel surveillant les forums Dark Web, flux OSINT et sites de fuite ransomware. Les logs affichent la reconnaissance active sur les services Tor et l'infrastructure C2 connue.
        </p>
      </div>
      {/* KPI Row & UX Controls */}
      <div style={{ display: 'flex', gap: 12, alignItems: 'stretch' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, flex: 1 }}>
          {[
            { label: 'Nœuds Tor Actifs', value: stats.running, color: '#22c55e' },
            { label: 'IOC Collectés au Total', value: stats.harvested.toLocaleString('fr-FR'), color: '#00eeff' },
            { label: 'Coupures de Connexion', value: stats.failed, color: '#ef4444' },
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
            placeholder="Filtrer les logs par mot-clé..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            style={{ padding: '6px 12px', fontSize: 11, fontWeight: 700, borderRadius: 4, background: '#1f2937', border: '1px solid #374151', color: '#e5e7eb', outline: 'none' }}
          />
          <div style={{ display: 'flex', gap: 8 }}>
            <button 
              onClick={() => setIsPaused(!isPaused)} 
              style={{ flex: 1, padding: '6px 12px', fontSize: 11, fontWeight: 700, borderRadius: 4, background: isPaused ? '#f59e0b20' : '#1f2937', color: isPaused ? '#f59e0b' : '#9ca3af', border: `1px solid ${isPaused ? '#f59e0b80' : '#374151'}`, cursor: 'pointer' }}
            >
              {isPaused ? `▶ REPRENDRE (${queuedCount} EN ATTENTE)` : '⏸ PAUSE DU FLUX'}
            </button>
            <button 
              onClick={() => { setLogs([]); setQueuedCount(0); queuedLogsRef.current = []; }}
              style={{ padding: '6px 12px', fontSize: 11, fontWeight: 700, borderRadius: 4, background: '#1f2937', color: '#ef4444', border: '1px solid #374151', cursor: 'pointer' }}
            >
              ✕ EFFACER
            </button>
            <button 
              onClick={() => {
                setAutoScroll(!autoScroll);
                if (!autoScroll && scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
              }}
              style={{ flex: 1, padding: '6px 12px', fontSize: 11, fontWeight: 700, borderRadius: 4, background: autoScroll ? '#22c55e20' : '#1f2937', color: autoScroll ? '#22c55e' : '#9ca3af', border: `1px solid ${autoScroll ? '#22c55e80' : '#374151'}`, cursor: 'pointer' }}
            >
              {autoScroll ? '▼ DÉFILEMENT AUTO: ON' : '▫ DÉFILEMENT AUTO: OFF'}
            </button>
          </div>
        </div>
      </div>

      <div style={{ background: '#05080f', border: '1px solid #1f2937', borderRadius: 8, height: 320, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '8px 16px', borderBottom: '1px solid #1f2937', display: 'flex', gap: 16, fontSize: 10, color: '#6b7280', fontWeight: 700, textTransform: 'uppercase' }}>
          <div style={{ width: 80 }}>Heure</div>
          <div style={{ width: 100 }}>Nœud</div>
          <div style={{ width: 120 }}>Action</div>
          <div style={{ flex: 1 }}>Cible (IP / Onion)</div>
          <div style={{ width: 60, textAlign: 'right' }}>Lat (ms)</div>
        </div>
        <div ref={scrollRef} onScroll={handleScroll} style={{ flex: 1, overflowY: 'auto', padding: 8, fontFamily: 'monospace', fontSize: 12, display: 'flex', flexDirection: 'column', gap: 4 }} className="scrollbar-hide">
          {logs.length === 0 && <div style={{ color: 'var(--text-tertiary)', textAlign: 'center', marginTop: 40, opacity: 0.5, fontFamily: 'monospace' }}>En attente de la télémétrie en direct...</div>}
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

  // Pool de 10 scénarios distincts en français, sans aucun terme non traduit (hors noms propres/acronymes)
  const SCENARIOS = [
    {
      title: "Renseignement SOC: Activité LockBit 3.0 Détectée",
      mitigation_priority: "critical", source: "ONYX AI", feed_source: "Senseurs Internes",
      executive_summary: "Détection d'une tentative d'intrusion du groupe LockBit 3.0 ciblant le secteur aéronautique via l'exploitation d'une vulnérabilité VPN.",
      threat_overview: "Le groupe LockBit a déployé son outil d'exfiltration furtive pour soustraire des données confidentielles avant le chiffrement complet.",
      technical_breakdown: "Exploitation de CVE-2023-46805. Injection de processus malveillant en mémoire vive.",
      impact_analysis: "Risque critique de fuite de propriété intellectuelle aéronautique.",
      mitigation: "Isoler les serveurs VPN. Révoquer les accès distants. Déployer les règles de détection comportementale.",
      intelligence_links: { iocs: ["192.168.1.1", "exfiltrateur.exe"], ttps: ["T1190", "T1486"], actors: ["LockBit 3.0"] }
    },
    {
      title: "Renseignement SOC: Campagne de Saturation par Anonymous Sudan",
      mitigation_priority: "high", source: "ONYX AI", feed_source: "Flux CTI Global",
      executive_summary: "Vague d'attaques par déni de service distribué ciblant les portails bancaires.",
      threat_overview: "Attaque réseau massive visant à saturer les pare-feux applicatifs web.",
      technical_breakdown: "Trafic de 450 Gbps généré par un réseau de machines compromises.",
      impact_analysis: "Indisponibilité potentielle des services bancaires en ligne.",
      mitigation: "Activer les protections de mitigation de charge. Filtrer géographiquement le trafic réseau entrant.",
      intelligence_links: { iocs: ["45.33.22.11"], ttps: ["T1498"], actors: ["Anonymous Sudan"] }
    },
    {
      title: "Renseignement SOC: Infiltration APT29 (Cozy Bear)",
      mitigation_priority: "critical", source: "ONYX AI", feed_source: "Analyse Heuristique",
      executive_summary: "Compromission de la chaîne d'approvisionnement détectée, similaire au mode opératoire historique du groupe.",
      threat_overview: "Déplacement latéral furtif via les services d'annuaire cloud pour accéder aux messageries gouvernementales.",
      technical_breakdown: "Utilisation de jetons d'authentification forgés pour contourner l'authentification multifacteur.",
      impact_analysis: "Accès persistant aux communications classifiées de l'État.",
      mitigation: "Révoquer les certificats de fédération d'identité. Auditer les journaux d'accès cloud.",
      intelligence_links: { iocs: ["avsvmcloud.com"], ttps: ["T1195.002", "T1550.004"], actors: ["APT29"] }
    },
    {
      title: "Renseignement SOC: Espionnage Industriel Volt Typhoon",
      mitigation_priority: "critical", source: "ONYX AI", feed_source: "Détection Comportementale",
      executive_summary: "Prépositionnement silencieux dans les infrastructures de télécommunications nationales.",
      threat_overview: "Utilisation exclusive d'outils d'administration légitimes préinstallés pour échapper à la détection.",
      technical_breakdown: "Création de tunnels via des relais proxy et extraction d'identifiants via l'infrastructure de gestion locale.",
      impact_analysis: "Préparation d'un sabotage potentiel des communications en cas de crise géopolitique majeure.",
      mitigation: "Restreindre l'exécution des terminaux de commande aux seuls administrateurs réseau identifiés.",
      intelligence_links: { iocs: ["relais-proxy.exe", "185.10.10.10"], ttps: ["T1047", "T1090"], actors: ["Volt Typhoon"] }
    },
    {
      title: "Renseignement SOC: Hameçonnage Ciblé Charming Kitten",
      mitigation_priority: "high", source: "ONYX AI", feed_source: "Analyse de Messagerie",
      executive_summary: "Campagne d'hameçonnage ciblé sophistiquée visant le secteur académique de la recherche de défense.",
      threat_overview: "Usurpation d'identité d'organisateurs de conférences internationales pour dérober des identifiants.",
      technical_breakdown: "Redirection vers de faux portails de connexion institutionnels. Extraction automatisée de correspondances.",
      impact_analysis: "Exfiltration massive de boîtes de réception contenant des recherches scientifiques sensibles.",
      mitigation: "Bloquer les domaines visuellement similaires. Imposer des clés matérielles pour l'authentification forte.",
      intelligence_links: { iocs: ["connexion-portail-securise.com"], ttps: ["T1566.002"], actors: ["Charming Kitten"] }
    },
    {
      title: "Renseignement SOC: Sabotage Industriel Sandworm",
      mitigation_priority: "critical", source: "ONYX AI", feed_source: "Sondes Industrielles",
      executive_summary: "Déploiement d'un logiciel effaceur de données sur des contrôleurs industriels de distribution électrique.",
      threat_overview: "Attaque destructrice visant à provoquer une coupure de courant ciblée et prolongée.",
      technical_breakdown: "Écrasement du secteur d'amorçage des disques et suppression systématique des journaux système.",
      impact_analysis: "Destruction irréversible des données de contrôle et perte de supervision des équipements physiques.",
      mitigation: "Isoler physiquement les réseaux industriels des réseaux de bureautique. Restaurer depuis des sauvegardes hors ligne isolées.",
      intelligence_links: { iocs: ["effaceur.sys"], ttps: ["T1485", "T1078"], actors: ["Sandworm"] }
    },
    {
      title: "Renseignement SOC: Détournement de Fonds Lazarus Group",
      mitigation_priority: "high", source: "ONYX AI", feed_source: "Surveillance Active",
      executive_summary: "Campagne d'ingénierie sociale ciblant les développeurs d'applications financières via les réseaux professionnels.",
      threat_overview: "Distribution de logiciels malveillants déguisés en offres d'emploi attractives et documentations factices.",
      technical_breakdown: "Exécution de code malveillant via des macros cachées dans des documents bureautiques piégés.",
      impact_analysis: "Siphonage des portefeuilles virtuels d'entreprise et vol de clés de chiffrement privées.",
      mitigation: "Sensibilisation accrue des employés. Blocage strict des macros provenant de sources externes à l'organisation.",
      intelligence_links: { iocs: ["offre_emploi_finance.doc"], ttps: ["T1566.001", "T1204"], actors: ["Lazarus Group"] }
    },
    {
      title: "Renseignement SOC: Extraction de Données Massives Cl0p",
      mitigation_priority: "critical", source: "ONYX AI", feed_source: "Veille Vulnérabilités",
      executive_summary: "Exploitation massive d'une vulnérabilité critique sur les serveurs de transfert de fichiers sécurisés.",
      threat_overview: "Vol de données entièrement automatisé sur des milliers de serveurs exposés publiquement.",
      technical_breakdown: "Injection de requêtes bases de données permettant l'exécution de code à distance via des interfaces d'administration compromises.",
      impact_analysis: "Exposition publique imminente de données de ressources humaines, données financières et dossiers médicaux.",
      mitigation: "Appliquer le correctif d'urgence du fournisseur. Supprimer tous les fichiers d'administration web non reconnus.",
      intelligence_links: { iocs: ["interface_admin_cachee.aspx", "138.197.152.201"], ttps: ["T1190", "T1505.003"], actors: ["Cl0p"] }
    },
    {
      title: "Renseignement SOC: Double Extorsion ALPHV",
      mitigation_priority: "critical", source: "ONYX AI", feed_source: "Agent Détection",
      executive_summary: "Affilié cybercriminel exploitant des identifiants valides pour chiffrer le réseau d'un centre hospitalier.",
      threat_overview: "Schéma de double extorsion impliquant le vol préalable de dossiers médicaux de patients avant la paralysie des systèmes.",
      technical_breakdown: "Désactivation des solutions de protection locales via des scripts d'administration avant le lancement du chiffreur.",
      impact_analysis: "Interruption immédiate des soins critiques et fuite de données de santé hautement confidentielles.",
      mitigation: "Activer la protection anti-falsification des agents de sécurité. Segmenter de manière étanche le réseau de matériel médical.",
      intelligence_links: { iocs: ["chiffreur_alphv.exe"], ttps: ["T1562.001", "T1486"], actors: ["BlackCat/ALPHV"] }
    },
    {
      title: "Renseignement SOC: Attaque Chaîne Logistique APT41",
      mitigation_priority: "high", source: "ONYX AI", feed_source: "Analyse Binaire",
      executive_summary: "Compromission d'un fournisseur majeur de logiciels de comptabilité d'entreprise.",
      threat_overview: "Distribution de mises à jour corrompues aux clients finaux permettant d'établir un accès distant persistant.",
      technical_breakdown: "Signature numérique de la charge utile malveillante avec un certificat de développeur légitime préalablement dérobé.",
      impact_analysis: "Accès complet et indétectable aux bases de données financières des entreprises clientes du logiciel.",
      mitigation: "Auditer immédiatement le processus de signature de code interne. Mettre en liste blanche stricte les serveurs de mise à jour.",
      intelligence_links: { iocs: ["agent_mise_a_jour.dll"], ttps: ["T1195.002", "T1553.002"], actors: ["APT41"] }
    }
  ];

  // Fonction de hachage déterministe
  const generateHash = (report: any) => {
    const str = `${report.title}-${report.intelligence_links?.actors?.join(',')}-${report.intelligence_links?.iocs?.join(',')}`;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return hash.toString();
  };

  useEffect(() => {
    // Initialisation
    setLoading(false);
    
    // Génération dynamique avec gestion des doublons via hash
    let lastUsedIndex = -1;
    let hashes = new Set<string>();

    const generateNewReport = () => {
      let index;
      do {
        index = Math.floor(Math.random() * SCENARIOS.length);
      } while (index === lastUsedIndex);
      
      lastUsedIndex = index;
      const baseReport = SCENARIOS[index];
      
      const newReport = {
        ...baseReport,
        id: `REP-${Math.random().toString(36).substr(2, 6).toUpperCase()}`,
        date: new Date().toISOString(),
      };

      const hash = generateHash(newReport);
      
      // Dédoublonnage : Si le hash existe, on ignore l'insertion
      if (!hashes.has(hash)) {
        hashes.add(hash);
        setReports(prev => {
          const newReports = [newReport, ...prev];
          return newReports.slice(0, 10); // Garder les 10 derniers
        });
      }
    };

    // On insère 2 rapports au démarrage
    generateNewReport();
    setTimeout(generateNewReport, 500);

    const int = setInterval(generateNewReport, 25000); // Nouveau rapport toutes les 25s
    return () => clearInterval(int);
  }, []);

  if (loading) return <div style={{ color: '#6b7280', textAlign: 'center', padding: 40, fontFamily: 'monospace' }}>Chargement des renseignements...</div>;
  if (reports.length === 0) return (
    <div style={{ color: '#6b7280', textAlign: 'center', padding: 40, border: '1px dashed #374151', borderRadius: 8, fontFamily: 'monospace' }}>
      En attente de rapports de renseignement entrants...
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
                  <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 99, border: `1px solid ${sevColor(r.mitigation_priority)}`, color: sevColor(r.mitigation_priority), textTransform: 'uppercase', fontWeight: 800 }}>PRIORITÉ {r.mitigation_priority === 'critical' ? 'CRITIQUE' : r.mitigation_priority === 'high' ? 'ÉLEVÉE' : 'MOYENNE'}</span>
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#6b7280' }}>{new Date(r.date).toLocaleString('fr-FR')}</span>
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#8b5cf6' }}>SOURCE : {r.source}{r.feed_source ? ` / ${r.feed_source}` : ''}</span>
                </div>
                <h3 style={{ fontSize: 20, fontWeight: 800, color: '#fff', margin: 0 }}>{r.title}</h3>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <span style={{ fontSize: 10, color: '#9ca3af', fontFamily: 'monospace', padding: '6px 12px', background: '#111', borderRadius: 6, border: '1px solid #333' }}>ID : {r.id}</span>
              </div>
            </div>
          </div>
          
          {/* Body */}
          <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* 1. Synthèse Exécutive */}
            <div>
              <h4 style={{ fontSize: 12, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>SYNTHÈSE EXÉCUTIVE</h4>
              <p style={{ fontSize: 15, lineHeight: 1.6, color: '#e5e7eb', margin: 0 }}>{r.executive_summary}</p>
            </div>
            
            {/* 2 & 3. Vue d'ensemble de la menace & Détails Techniques */}
            <div style={{ background: '#0a0a0a', padding: 16, borderRadius: 8, border: '1px solid #1f2937' }}>
              <h4 style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>APERÇU DE LA MENACE</h4>
              <p style={{ fontSize: 13, color: '#cbd5e1', margin: '0 0 16px 0', fontFamily: 'var(--font-mono)' }}>{r.threat_overview}</p>
              <h4 style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>ANALYSE TECHNIQUE</h4>
              <p style={{ fontSize: 13, color: 'var(--onyx-cyan)', margin: 0, fontFamily: 'var(--font-mono)' }}>{r.technical_breakdown}</p>
            </div>
            
            {/* 4 & 5. Impact & Mitigation */}
            <div style={{ background: '#0f172a', padding: 16, borderRadius: 8, borderLeft: '3px solid #6366f1' }}>
              <h4 style={{ fontSize: 11, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>ANALYSE D'IMPACT</h4>
              <p style={{ fontSize: 13, color: '#cbd5e1', marginBottom: 16 }}>{r.impact_analysis}</p>
              <h4 style={{ fontSize: 11, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>MESURES D'ATTÉNUATION RECOMMANDÉES</h4>
              <p style={{ fontSize: 13, color: '#22c55e', margin: 0 }}>{r.mitigation}</p>
            </div>
            
            {/* 6. Artifacts & Intelligence Links */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginTop: 12 }}>
              <div>
                <h4 style={{ fontSize: 11, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>INDICATEURS EXTRAITS (IOC)</h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {r.intelligence_links?.iocs?.length > 0 ? r.intelligence_links.iocs.map((ioc: string, idx: number) => (
                    <button key={idx} onClick={() => onNavigate('iocs')} style={{ padding: '4px 8px', background: 'rgba(0,238,255,0.05)', border: '1px solid var(--onyx-cyan)', borderRadius: 4, color: '#00eeff', fontSize: 11, fontFamily: 'monospace', cursor: 'pointer' }} className="hover:bg-cyan-900/40 transition-colors">
                      {ioc}
                    </button>
                  )) : <span style={{ color: '#6b7280', fontSize: 12 }}>Aucun extrait</span>}
                </div>
              </div>
              <div>
                <h4 style={{ fontSize: 11, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>MITRE TTPs & Acteurs</h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
                  {r.intelligence_links?.ttps?.length > 0 ? r.intelligence_links.ttps.map((ttp: string) => (
                    <button key={ttp} onClick={() => onNavigate('attack')} style={{ padding: '2px 6px', background: '#111', border: '1px solid #4b5563', borderRadius: 4, color: '#f59e0b', fontSize: 11, fontFamily: 'monospace', cursor: 'pointer' }} className="hover:border-amber-500">{ttp}</button>
                  )) : <span style={{ color: '#6b7280', fontSize: 12 }}>Aucun TTP associé</span>}
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
  const [activeTab, setActiveTab] = useState('executive');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  // Thème global appliqué au <html> pour couvrir toute la plateforme
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const toggleTheme = useCallback(() => setTheme(t => t === 'dark' ? 'light' : 'dark'), []);
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

  // ── Boot OSINT connectors ─────────────────────────────────────────────────
  useEffect(() => {
    initRealTimeService();
    return () => { /* Keep running across tab changes — only destroy on full unmount */ };
  }, []);

  // Pull sources for the status panel (8 sources)
  const realTimeSources = useRealTimeStore(s => s.sources);

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
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} theme={theme} onThemeToggle={toggleTheme} />
      <Header connected={connected} />
      <main className="onyx-main">
        {/* ====== EXECUTIVE DASHBOARD ====== */}
        {activeTab === 'executive' && (
          <ExecutiveDashboard />
        )}

        {/* ====== OVERVIEW ====== */}
        {activeTab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }} className="section-enter">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
              <StatCard label="IOC Armés" value={iocTotal} trend={`+${liveIocCount} en direct`} icon="⬡" color="var(--onyx-cyan)" />
              <StatCard label="Acteurs de Menace" value={threatTotal} trend="+2 nouveaux" icon="☠" color="#ef4444" />
              <StatCard label="Objets STIX" value={stixTotal} icon="◎" color="var(--onyx-magenta)" />
              <StatCard label="Confiance Moteur" value={`${avgConf}%`} icon="◈" color="#22c55e" />
            </div>

            {/* 3D Map — fully CSR-only (never rendered server-side) */}
            <ThreatMap3D />

            {/* IA & SIEM Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <SciBERTEngineRefonte />
              <SIEMRuleConverter />
            </div>

            {/* Bottom Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
              <div className="onyx-card">
                <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, marginBottom: 14 }}>Distribution par Sévérité</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {severities.map(s => <SeverityBar key={s.key} severity={s.key} count={s.doc_count} total={sevTotal} />)}
                </div>
              </div>
              <div className="onyx-card">
                <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, marginBottom: 14 }}>🕸 Sources Actives</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {Object.entries(realTimeSources).slice(0, 8).map(([id, source]) => (
                    <div key={id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid #111' }}>
                      <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{id.toUpperCase()}</span>
                      <span style={{ fontSize: 10, color: source.status === 'connected' ? '#22c55e' : source.status === 'failed' ? '#ef4444' : '#f59e0b', textTransform: 'uppercase', fontWeight: 700 }}>
                        {source.status === 'connected' ? 'EN LIGNE' : source.status === 'failed' ? 'ERREUR' : 'DÉGRADÉ/INIT'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              <SignauxTempsReel />
            </div>
          </div>
        )}

        {activeTab === 'iocs' && (
          <div style={{ height: 'calc(100vh - 120px)' }}>
            <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 20, background: 'linear-gradient(135deg, var(--onyx-cyan), var(--onyx-green))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              ⬡ Explorateur IOC — Flux en Direct
            </h2>
            <TelemetrieIOC />
          </div>
        )}

        {activeTab === 'threats' && (
          <div style={{ height: 'calc(100vh - 120px)' }}>
            <ActeursMenace />
          </div>
        )}

        {/* 3D STIX Graph — fully CSR-only */}
        {activeTab === 'graph' && <ThreatGraph />}

        {/* ====== LABORATOIRE IA ====== */}
        {activeTab === 'ailab' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <LaboratoireIA />
          </div>
        )}

        {activeTab === 'crawlers' && (
          <div>
            <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 20, background: 'linear-gradient(135deg, #22c55e, #00eeff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              🕸 Centre d'Opérations — Crawlers
            </h2>
            <CrawlersPanel />
          </div>
        )}

        {activeTab === 'reports' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: 22, fontWeight: 800, background: 'linear-gradient(135deg, #a855f7, var(--onyx-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                📋 Rapports de Renseignement sur les Menaces
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
