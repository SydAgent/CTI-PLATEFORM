'use client';

/**
 * GC-03: ConvergenceBadge + ConvergencePeersPanel
 *
 * ConvergenceBadge: inline pill shown when Jaccard ≥ 0.65 with the highest peer.
 * ConvergencePeersPanel: full panel listing all convergent peers with Jaccard bars.
 */

import React, { useEffect, useState } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const CONVERGENCE_THRESHOLD = 0.65;

interface ConvergenceResult {
  actor_a: string;
  actor_b: string;
  jaccard_score: number;
  shared_techniques: string[];
  unique_to_a: string[];
  unique_to_b: string[];
  convergent: boolean;
  interpretation: string;
}

interface ConvergencePeersResponse {
  actor_id: string;
  threshold: number;
  peers: ConvergenceResult[];
}

function jaccardColor(score: number): string {
  if (score >= 0.80) return '#ef4444';
  if (score >= 0.65) return '#f97316';
  if (score >= 0.40) return '#eab308';
  return '#6b7280';
}

// ─── Compact badge for inline display ────────────────────────────────────────

export function ConvergenceBadge({ actorId }: { actorId: string }) {
  const [topPeer, setTopPeer] = useState<ConvergenceResult | null>(null);

  useEffect(() => {
    fetch(`${API}/api/v1/actors/${encodeURIComponent(actorId)}/convergence-peers?min_jaccard=0.65`)
      .then(r => r.ok ? r.json() : null)
      .then((d: ConvergencePeersResponse | null) => {
        if (d && d.peers.length > 0) setTopPeer(d.peers[0]);
      })
      .catch(() => null);
  }, [actorId]);

  if (!topPeer) return null;

  const color = jaccardColor(topPeer.jaccard_score);
  const pct = Math.round(topPeer.jaccard_score * 100);

  return (
    <span
      title={`Convergence comportementale avec ${topPeer.actor_b} — ${pct}% TTPs partagés\n${topPeer.interpretation}`}
      className="inline-flex items-center gap-1 text-[8px] font-mono font-bold px-1.5 py-0.5 rounded cursor-help"
      style={{ background: `${color}15`, color, border: `1px solid ${color}40` }}
    >
      <span aria-hidden="true">⟺</span>
      {topPeer.actor_b} {pct}%
    </span>
  );
}

// ─── Full panel ───────────────────────────────────────────────────────────────

export interface ConvergencePeersPanelProps {
  actorId: string;
  actorName: string;
}

export default function ConvergencePeersPanel({ actorId, actorName }: ConvergencePeersPanelProps) {
  const [data, setData] = useState<ConvergencePeersResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`${API}/api/v1/actors/${encodeURIComponent(actorId)}/convergence-peers?min_jaccard=0.25`)
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
        <span className="animate-spin">⟳</span> Analyse de convergence comportementale…
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="text-xs font-mono text-gray-600 py-4">
        {error ? `Erreur : ${error}` : 'Aucune donnée de convergence.'}
      </div>
    );
  }

  const convergent = data.peers.filter(p => p.convergent);
  const similar = data.peers.filter(p => !p.convergent);

  return (
    <div className="flex flex-col gap-3">
      {/* Summary header */}
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-[9px] font-mono text-gray-500 uppercase tracking-wider">
          Similarité Jaccard (TTPs) · seuil convergence :
        </span>
        <span className="text-[9px] font-bold font-mono"
          style={{ color: '#f97316' }}>
          {Math.round(CONVERGENCE_THRESHOLD * 100)}%
        </span>
        <span className="ml-auto text-[9px] font-mono text-gray-600">
          {convergent.length} convergent(s) · {similar.length} similaire(s)
        </span>
      </div>

      {/* Convergent peers */}
      {convergent.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <div className="text-[9px] font-mono font-bold uppercase tracking-wider text-orange-400 flex items-center gap-1">
            <span>⚠</span> Convergence Comportementale Détectée
          </div>
          {convergent.map(peer => (
            <PeerRow
              key={peer.actor_b}
              peer={peer}
              isExpanded={expanded === peer.actor_b}
              onToggle={() => setExpanded(e => e === peer.actor_b ? null : peer.actor_b)}
            />
          ))}
        </div>
      )}

      {/* Similar peers */}
      {similar.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <div className="text-[9px] font-mono font-bold uppercase tracking-wider text-gray-500">
            Acteurs Similaires
          </div>
          {similar.map(peer => (
            <PeerRow
              key={peer.actor_b}
              peer={peer}
              isExpanded={expanded === peer.actor_b}
              onToggle={() => setExpanded(e => e === peer.actor_b ? null : peer.actor_b)}
            />
          ))}
        </div>
      )}

      {data.peers.length === 0 && (
        <div className="text-xs font-mono text-gray-600 text-center py-4 bg-[#0a0f1a] rounded border border-gray-800/30">
          Aucune convergence comportementale détectée pour cet acteur.
        </div>
      )}

      <p className="text-[8px] font-mono text-gray-700">
        Similarité de Jaccard sur ensembles de TTPs MITRE ATT&CK · Threshold ≥ {Math.round(CONVERGENCE_THRESHOLD * 100)}% = convergent
      </p>
    </div>
  );
}

function PeerRow({
  peer,
  isExpanded,
  onToggle,
}: {
  peer: ConvergenceResult;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const color = jaccardColor(peer.jaccard_score);
  const pct = Math.round(peer.jaccard_score * 100);

  return (
    <div
      className="rounded border overflow-hidden"
      style={{ borderColor: peer.convergent ? `${color}40` : '#1f2937' }}
    >
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-3 py-2 hover:bg-white/5 transition-colors"
        style={{ background: peer.convergent ? `${color}08` : '#0a0f1a' }}
      >
        {/* Actor name */}
        <span className="text-xs font-bold font-mono min-w-[120px] text-left"
          style={{ color: peer.convergent ? color : '#9ca3af' }}>
          {peer.actor_b}
          {peer.convergent && (
            <span className="ml-1.5 text-[7px] px-1 py-0.5 rounded"
              style={{ background: `${color}20`, color, border: `1px solid ${color}40` }}>
              CONVERGENT
            </span>
          )}
        </span>

        {/* Jaccard bar */}
        <div className="flex items-center gap-1.5 flex-1 min-w-0">
          <div className="flex-1 h-1.5 rounded-full bg-gray-800 overflow-hidden">
            <div
              className="h-full rounded-full transition-all"
              style={{ width: `${pct}%`, background: color }}
            />
          </div>
          <span className="text-[9px] font-mono font-bold shrink-0"
            style={{ color, minWidth: 30, textAlign: 'right' }}>
            {pct}%
          </span>
        </div>

        {/* Shared count */}
        <span className="text-[9px] font-mono text-gray-600 shrink-0">
          {peer.shared_techniques.length} TTPs communs
        </span>

        <span className="text-gray-600 text-[10px]">{isExpanded ? '▴' : '▾'}</span>
      </button>

      {isExpanded && (
        <div className="px-3 pb-3 pt-1" style={{ background: '#04060a' }}>
          {/* Interpretation */}
          <p className="text-[9px] font-mono text-gray-400 mb-2 leading-relaxed">
            {peer.interpretation}
          </p>

          {/* Shared techniques */}
          {peer.shared_techniques.length > 0 && (
            <div className="mb-2">
              <div className="text-[8px] font-mono text-gray-600 uppercase mb-1">TTPs Partagés</div>
              <div className="flex flex-wrap gap-1">
                {peer.shared_techniques.map(t => (
                  <span key={t} className="text-[8px] font-mono px-1 py-0.5 rounded"
                    style={{ background: `${color}15`, color, border: `1px solid ${color}30` }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Unique to this actor */}
          {peer.unique_to_a.length > 0 && (
            <div>
              <div className="text-[8px] font-mono text-gray-600 uppercase mb-1">
                Exclusifs à {peer.actor_a} ({peer.unique_to_a.length})
              </div>
              <div className="flex flex-wrap gap-1">
                {peer.unique_to_a.slice(0, 8).map(t => (
                  <span key={t} className="text-[8px] font-mono px-1 py-0.5 rounded bg-gray-800 text-gray-500">
                    {t}
                  </span>
                ))}
                {peer.unique_to_a.length > 8 && (
                  <span className="text-[8px] font-mono text-gray-600">+{peer.unique_to_a.length - 8}</span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
