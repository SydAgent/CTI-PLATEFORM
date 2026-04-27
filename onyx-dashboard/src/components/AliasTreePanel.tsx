'use client';

/**
 * GC-02: AliasTreePanel
 *
 * Fetches alias disambiguation data from GET /actors/{id}/aliases and renders:
 * - Canonical name badge
 * - Sorted alias list with certainty bar + source chips
 * - Disputed aliases highlighted with warning badge
 */

import React, { useEffect, useState } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface AliasNode {
  alias: string;
  canonical: string;
  certainty: number;
  sources: string[];
  disputed: boolean;
  note: string;
}

interface AliasListResponse {
  actor_id: string;
  canonical: string | null;
  aliases: AliasNode[];
  total: number;
}

const SOURCE_COLORS: Record<string, string> = {
  MITRE:          '#00eeff',
  CrowdStrike:    '#f97316',
  Mandiant:       '#ef4444',
  Microsoft:      '#3b82f6',
  ESET:           '#22c55e',
  Kaspersky:      '#a855f7',
  RecordedFuture: '#eab308',
  Unit42:         '#ec4899',
  TrendMicro:     '#06b6d4',
  Proofpoint:     '#8b5cf6',
  Dragos:         '#14b8a6',
  Symantec:       '#6366f1',
  FBI:            '#dc2626',
  CISA:           '#dc2626',
  'US-CERT':      '#dc2626',
  IBM:            '#64748b',
  Volexity:       '#84cc16',
};

function certaintyColor(c: number): string {
  if (c >= 0.90) return '#22c55e';
  if (c >= 0.75) return '#eab308';
  if (c >= 0.50) return '#f97316';
  return '#ef4444';
}

export interface AliasTreePanelProps {
  actorId: string;
  actorName: string;
}

export default function AliasTreePanel({ actorId, actorName }: AliasTreePanelProps) {
  const [data, setData] = useState<AliasListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`${API}/api/v1/actors/${encodeURIComponent(actorId)}/aliases`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [actorId]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-gray-600 text-xs font-mono py-4">
        <span className="animate-spin">⟳</span> Résolution des alias…
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="text-xs font-mono text-gray-600 py-4">
        {error ? `Erreur : ${error}` : 'Aucune donnée d\'alias disponible.'}
      </div>
    );
  }

  const disputed = data.aliases.filter(a => a.disputed);
  const clean = data.aliases.filter(a => !a.disputed);

  return (
    <div className="flex flex-col gap-3">
      {/* Canonical name + summary */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[9px] font-mono text-gray-500 uppercase tracking-wider">Nom canonique :</span>
        {data.canonical ? (
          <span
            className="text-xs font-bold font-mono px-2 py-0.5 rounded"
            style={{ background: '#00eeff15', color: '#00eeff', border: '1px solid #00eeff40' }}
          >
            {data.canonical}
          </span>
        ) : (
          <span className="text-xs font-mono text-gray-600">Non résolu (entrée directe)</span>
        )}
        <span className="ml-auto text-[9px] font-mono text-gray-600">
          {data.total} alias · {disputed.length > 0 ? `${disputed.length} contesté(s)` : 'aucun contesté'}
        </span>
      </div>

      {/* Disputed aliases — warning section */}
      {disputed.length > 0 && (
        <div
          className="rounded-lg p-2 border"
          style={{ background: '#7c2d1215', borderColor: '#f9731640' }}
        >
          <div className="flex items-center gap-1.5 mb-2 text-[9px] font-mono font-bold text-orange-400 uppercase tracking-wider">
            <span>⚠</span> Alias Contestés
          </div>
          <div className="flex flex-col gap-1.5">
            {disputed.map(node => (
              <AliasRow key={node.alias} node={node} isDisputed />
            ))}
          </div>
        </div>
      )}

      {/* Clean aliases */}
      {clean.length > 0 ? (
        <div className="flex flex-col gap-1.5">
          {clean.map(node => (
            <AliasRow key={node.alias} node={node} />
          ))}
        </div>
      ) : (
        <div className="text-xs font-mono text-gray-600 text-center py-3 bg-[#0a0f1a] rounded border border-gray-800/30">
          Aucun alias connu dans la base ONYX pour cet acteur.
        </div>
      )}

      <p className="text-[8px] font-mono text-gray-700 mt-1">
        Sources : MITRE ATT&CK · CrowdStrike · Mandiant · Microsoft · Kaspersky · ESET · Proofpoint · Dragos · RecordedFuture
      </p>
    </div>
  );
}

function AliasRow({ node, isDisputed = false }: { node: AliasNode; isDisputed?: boolean }) {
  const color = certaintyColor(node.certainty);
  const pct = Math.round(node.certainty * 100);

  return (
    <div
      className="flex items-center gap-3 px-2 py-1.5 rounded"
      style={{ background: isDisputed ? '#7c2d1208' : '#0a0f1a', border: `1px solid ${isDisputed ? '#f9731630' : '#1f2937'}` }}
    >
      {/* Alias name */}
      <span
        className="text-xs font-bold font-mono min-w-[140px]"
        style={{ color: isDisputed ? '#f97316' : '#e5e7eb' }}
      >
        {node.alias}
        {isDisputed && (
          <span className="ml-1.5 text-[8px] px-1 py-0.5 rounded"
            style={{ background: '#f9731620', color: '#f97316', border: '1px solid #f9731640' }}>
            CONTESTÉ
          </span>
        )}
      </span>

      {/* Certainty bar */}
      <div className="flex items-center gap-1.5 flex-1 min-w-0">
        <div className="flex-1 h-1.5 rounded-full bg-gray-800 overflow-hidden">
          <div
            className="h-full rounded-full transition-all"
            style={{ width: `${pct}%`, background: color }}
          />
        </div>
        <span
          className="text-[9px] font-mono font-bold shrink-0"
          style={{ color, minWidth: 30, textAlign: 'right' }}
        >
          {pct}%
        </span>
      </div>

      {/* Source chips */}
      <div className="flex items-center gap-1 shrink-0 flex-wrap justify-end" style={{ maxWidth: 200 }}>
        {node.sources.slice(0, 4).map(src => {
          const c = SOURCE_COLORS[src] ?? '#6b7280';
          return (
            <span
              key={src}
              className="text-[7px] font-mono px-1 py-0.5 rounded"
              style={{ background: `${c}18`, color: c, border: `1px solid ${c}40` }}
            >
              {src}
            </span>
          );
        })}
        {node.sources.length > 4 && (
          <span className="text-[7px] font-mono text-gray-600">+{node.sources.length - 4}</span>
        )}
      </div>
    </div>
  );
}
