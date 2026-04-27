'use client';

import React, { useState, useMemo } from 'react';
import { useRealTimeStore } from '@/lib/RealTimeDataService';

// Unified IOC Type
interface IOC {
  id: string;
  type: string;
  value: string;
  source: string;
  confidence: number;
  date: string;
}

export default function IoCTable({ actorId, fallbackIocs }: { actorId?: string; fallbackIocs?: any[] }) {
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;

  // Aggregate data from all real-time connectors
  const rawIocs = useRealTimeStore((state) => {
    const list: IOC[] = [];

    state.urlhaus?.forEach(i => list.push({ id: i.id || crypto.randomUUID(), type: 'url', value: i.url, source: 'URLhaus', confidence: 95, date: i.date_added || new Date().toISOString() }));
    state.threatfox?.forEach(i => list.push({ id: i.id || crypto.randomUUID(), type: i.ioc_type?.includes('ip') ? 'ipv4' : i.ioc_type || 'hash', value: i.ioc, source: 'ThreatFox', confidence: i.confidence_level || 90, date: i.first_seen || new Date().toISOString() }));
    state.circl?.forEach(i => list.push({ id: crypto.randomUUID(), type: i.type || 'unknown', value: i.value, source: 'CIRCL MISP', confidence: 85, date: i.timestamp || i.date || new Date().toISOString() }));
    state.openphish?.forEach(i => list.push({ id: crypto.randomUUID(), type: 'url', value: i.url, source: 'OpenPhish', confidence: 99, date: i.date || new Date().toISOString() }));
    
    const alienvault = (state as any).alienvault;
    if (alienvault) {
      alienvault.forEach((i: any) => list.push({ id: crypto.randomUUID(), type: i.type || 'domain', value: i.indicator, source: 'OTX', confidence: 80, date: i.created || new Date().toISOString() }));
    }

    // Include fallback if provided and if we don't have enough live data yet
    if (fallbackIocs && list.length === 0) {
      fallbackIocs.forEach((i: any) => {
        list.push({
          id: i.id || crypto.randomUUID(),
          type: i.type || 'ipv4',
          value: i.value,
          source: i.source || 'Fallback',
          confidence: i.confidence || 90,
          date: i.date_detection || i.timestamp || new Date().toISOString()
        });
      });
    }

    // Deduplication using Map (last occurrence wins, but we'll sort anyway)
    const dedupMap = new Map<string, IOC>();
    list.forEach(item => {
      dedupMap.set(item.value, item);
    });

    return Array.from(dedupMap.values());
  });

  const sortedIocs = useMemo(() => {
    return rawIocs.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  }, [rawIocs]);

  const filtered = sortedIocs.filter(ioc => {
    const matchSearch = ioc.value.toLowerCase().includes(filter.toLowerCase()) || ioc.source.toLowerCase().includes(filter.toLowerCase());
    
    let matchType = typeFilter === 'all';
    if (!matchType) {
      const t = ioc.type.toLowerCase();
      if (typeFilter === 'url') matchType = t.includes('url');
      if (typeFilter === 'ipv4') matchType = t.includes('ip');
      if (typeFilter === 'domain') matchType = t.includes('domain');
      if (typeFilter === 'hash') matchType = t.includes('hash') || t.includes('sha') || t.includes('md5');
    }

    let matchSource = sourceFilter === 'all';
    if (!matchSource) {
      matchSource = ioc.source.toLowerCase().includes(sourceFilter.toLowerCase());
    }

    return matchSearch && matchType && matchSource;
  });

  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));

  const confColor = (c: number) => c >= 95 ? '#ef4444' : c >= 80 ? '#f97316' : '#eab308';
  
  const getFreshness = (dateStr: string) => {
    const hours = Math.max(0, (Date.now() - new Date(dateStr).getTime()) / 3600000);
    if (hours < 1) return { text: '< 1h', color: '#00eeff' };
    if (hours < 24) return { text: `${Math.floor(hours)}h`, color: '#22c55e' };
    return { text: `${Math.floor(hours / 24)}d`, color: '#6b7280' };
  };

  const IOCTypeBadge = ({ type }: { type: string }) => {
    let normalized = 'OTHER';
    const t = type.toLowerCase();
    if (t.includes('ip')) normalized = 'IPV4';
    else if (t.includes('url')) normalized = 'URL';
    else if (t.includes('domain')) normalized = 'DOMAIN';
    else if (t.includes('sha') || t.includes('md5') || t.includes('hash')) normalized = 'HASH';
    
    const colors: Record<string, string> = {
      IPV4: 'var(--onyx-cyan)', DOMAIN: 'var(--onyx-magenta)', URL: 'var(--onyx-amber)',
      HASH: 'var(--onyx-green)', OTHER: 'var(--text-tertiary)'
    };
    
    return (
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', padding: '3px 8px', borderRadius: 'var(--radius-full)', background: `${colors[normalized] || colors.OTHER}22`, color: colors[normalized] || colors.OTHER, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        {normalized}
      </span>
    );
  };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          type="text"
          placeholder="Rechercher IP, hash, source..."
          value={filter}
          onChange={e => { setFilter(e.target.value); setPage(1); }}
          style={{ flex: 1, minWidth: 180, background: '#0a0a0a', border: '1px solid #1f2937', borderRadius: 8, padding: '8px 14px', color: '#e5e7eb', fontSize: 12, fontFamily: 'monospace', outline: 'none' }}
        />
        
        {/* Type Filter */}
        <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(1); }} style={{ padding: '8px 14px', borderRadius: 8, border: '1px solid #1f2937', background: '#0a0a0a', color: '#e5e7eb', fontSize: 11, fontFamily: 'monospace', outline: 'none' }}>
          <option value="all">TOUS TYPES</option>
          <option value="ipv4">IPv4</option>
          <option value="url">URL</option>
          <option value="domain">Domaine</option>
          <option value="hash">Hash</option>
        </select>

        {/* Source Filter */}
        <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(1); }} style={{ padding: '8px 14px', borderRadius: 8, border: '1px solid #1f2937', background: '#0a0a0a', color: '#e5e7eb', fontSize: 11, fontFamily: 'monospace', outline: 'none' }}>
          <option value="all">TOUTES SOURCES</option>
          <option value="urlhaus">URLhaus</option>
          <option value="threatfox">ThreatFox</option>
          <option value="otx">OTX</option>
          <option value="circl">CIRCL MISP</option>
          <option value="openphish">OpenPhish</option>
        </select>

        <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#22c55e', padding: '8px 0', alignSelf: 'center' }}>
          {filtered.length.toLocaleString()} indicateurs
        </span>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', borderRadius: 10, border: '1px solid #1f2937', marginBottom: 12 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, fontFamily: 'monospace' }}>
          <thead>
            <tr style={{ background: '#090909', borderBottom: '1px solid #1f2937', position: 'sticky', top: 0, zIndex: 1 }}>
              {['TYPE', 'VALEUR', 'SOURCE', 'FRAÎCHEUR', 'CONFIANCE', 'ACTION'].map(h => (
                <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontSize: 10, color: '#4b5563', letterSpacing: '0.08em', fontWeight: 700 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paginated.map((ioc, i) => {
              const freshness = getFreshness(ioc.date);
              return (
                <tr key={i} style={{ borderBottom: '1px solid #111', transition: 'background 0.15s' }}
                  onMouseEnter={e => (e.currentTarget.style.background = '#0d1117')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <td style={{ padding: '9px 14px' }}><IOCTypeBadge type={ioc.type} /></td>
                  <td style={{ padding: '9px 14px', color: '#e5e7eb', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.value}</td>
                  <td style={{ padding: '9px 14px', color: '#6b7280', fontSize: 11 }}>{ioc.source}</td>
                  <td style={{ padding: '9px 14px', color: freshness.color, fontSize: 11, fontWeight: 700 }}>
                    {freshness.text}
                  </td>
                  <td style={{ padding: '9px 14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 50, height: 4, background: '#1f2937', borderRadius: 99 }}>
                        <div style={{ width: `${ioc.confidence}%`, height: '100%', background: confColor(ioc.confidence), borderRadius: 99 }} />
                      </div>
                      <span style={{ padding: '2px 6px', background: `${confColor(ioc.confidence)}1A`, border: `1px solid ${confColor(ioc.confidence)}40`, borderRadius: 4, color: confColor(ioc.confidence), fontSize: 10, fontWeight: 700 }}>
                        {ioc.confidence.toFixed(0)}%
                      </span>
                    </div>
                  </td>
                  <td style={{ padding: '9px 14px' }}>
                    <button onClick={() => window.open(`https://www.virustotal.com/gui/search/${encodeURIComponent(ioc.value)}`, '_blank')} style={{ fontSize: 10, padding: '4px 10px', border: '1px solid #374151', borderRadius: 4, background: 'transparent', color: '#9ca3af', cursor: 'pointer', transition: 'all 0.2s' }} onMouseEnter={e => { e.currentTarget.style.borderColor = '#00eeff'; e.currentTarget.style.color = '#00eeff'; }} onMouseLeave={e => { e.currentTarget.style.borderColor = '#374151'; e.currentTarget.style.color = '#9ca3af'; }}>
                      HUNT
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 16 }}>
        <button 
          onClick={() => setPage(p => Math.max(1, p - 1))} 
          disabled={page === 1}
          style={{ padding: '6px 12px', background: '#0a0a0a', border: '1px solid #1f2937', borderRadius: 6, color: page === 1 ? '#4b5563' : '#00eeff', cursor: page === 1 ? 'not-allowed' : 'pointer', fontFamily: 'monospace' }}
        >
          &lt; Précédent
        </button>
        <span style={{ fontSize: 12, fontFamily: 'monospace', color: '#9ca3af' }}>
          Page {page} / {totalPages}
        </span>
        <button 
          onClick={() => setPage(p => Math.min(totalPages, p + 1))} 
          disabled={page === totalPages}
          style={{ padding: '6px 12px', background: '#0a0a0a', border: '1px solid #1f2937', borderRadius: 6, color: page === totalPages ? '#4b5563' : '#00eeff', cursor: page === totalPages ? 'not-allowed' : 'pointer', fontFamily: 'monospace' }}
        >
          Suivant &gt;
        </button>
      </div>
    </div>
  );
}
