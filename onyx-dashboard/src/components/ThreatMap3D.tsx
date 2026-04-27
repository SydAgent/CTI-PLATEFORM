"use client";

import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import Map from 'react-map-gl/maplibre';
import 'maplibre-gl/dist/maplibre-gl.css';
import DeckGL from '@deck.gl/react';
import { ScatterplotLayer, ArcLayer, PathLayer } from '@deck.gl/layers';
import { Line, Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, BarElement, Title, Tooltip as ChartTooltip, Legend, Filler, ArcElement } from 'chart.js';
import { useRealTimeStore, type GDELTEvent } from '@/lib/RealTimeDataService';
import { useRouter } from 'next/navigation';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Title, ChartTooltip, Legend, Filler);

const MAP_STYLE = 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json';

// formatRelativeTime moved down

function CriticalityBar({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-2 mt-1">
      <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden flex">
         <div className="h-full bg-rose-500" style={{ width: `${(score / 10) * 100}%` }}></div>
      </div>
      <span className="text-xs font-mono text-slate-300">{score}/10</span>
    </div>
  );
}

function Badge({ children, color }: { children: React.ReactNode, color?: string }) {
  return (
    <span className={`px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider rounded border ${color || 'bg-slate-800 text-slate-300 border-slate-700'}`}>
      {children}
    </span>
  );
}

type RightPanelMode = 
  | { type: 'idle' }
  | { type: 'actor-analysis'; actor: any }
  | { type: 'attack-flow'; flow: any }
  | { type: 'similar-events'; reference: any; similar: any[] };

function ActorAnalysisPanel({ actor, onClose }: { actor: any, onClose: () => void }) {
  const router = useRouter();
  const panelRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    function updatePanelHeight() {
      const panel = panelRef.current;
      if (!panel) return;
      const top = panel.getBoundingClientRect().top;
      const availableHeight = window.innerHeight - top - 16; // 16px de marge bas
      panel.style.maxHeight = `${availableHeight}px`;
    }
    
    updatePanelHeight();
    window.addEventListener('resize', updatePanelHeight);
    return () => window.removeEventListener('resize', updatePanelHeight);
  }, [actor]);

  return (
    <div ref={panelRef} className="w-full h-full flex flex-col pointer-events-auto">
      <header className="shrink-0 p-4 border-b border-slate-700 flex justify-between items-start">
        <div>
          <span className="text-xs uppercase tracking-wider text-orange-400">Acteur</span>
          <h3 className="text-xl font-bold text-white">{actor.name}</h3>
          {actor.aliases && actor.aliases.length > 0 && (
            <p className="text-xs text-slate-400 mt-1">
              Alias : {actor.aliases.join(', ')}
            </p>
          )}
        </div>
        <button onClick={onClose} className="text-slate-400 hover:text-white">✕</button>
      </header>

      <div className="flex-1 min-h-0 p-4 space-y-4 overflow-y-auto onyx-scrollbar">
        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Origine</h4>
          <p className="text-sm text-white">{actor.country ?? 'Inconnue'}</p>
        </section>

        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Motivation</h4>
          <Badge>{actor.motivation ?? 'Non renseignée'}</Badge>
        </section>

        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Secteurs ciblés</h4>
          <div className="flex flex-wrap gap-1">
            {actor.targetedSectors?.map((s: string) => <Badge key={s}>{s}</Badge>)}
          </div>
        </section>

        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Top 5 TTPs MITRE</h4>
          <ul className="space-y-1">
            {actor.topTTPs?.slice(0, 5).map((ttp: any) => (
              <li key={ttp.id} className="text-xs text-slate-300">
                <span className="text-cyan-400">{ttp.id}</span> — {ttp.name}
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Activité récente</h4>
          <p className="text-sm text-slate-300">{actor.lastObservedActivity ?? 'Non renseignée'}</p>
        </section>
      </div>

      <footer className="shrink-0 p-4 border-t border-slate-700 bg-slate-900/95">
        <button 
          onClick={() => router.push(`/acteurs-menace?actor=${encodeURIComponent(actor.name)}`)}
          className="w-full px-3 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 rounded text-sm transition-colors"
        >
          📊 Voir la fiche complète
        </button>
      </footer>
    </div>
  );
}

function AttackFlowPanel({ flow, onClose }: { flow: any, onClose: () => void }) {
  const panelRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    function updatePanelHeight() {
      const panel = panelRef.current;
      if (!panel) return;
      const top = panel.getBoundingClientRect().top;
      const availableHeight = window.innerHeight - top - 16;
      panel.style.maxHeight = `${availableHeight}px`;
    }
    
    updatePanelHeight();
    window.addEventListener('resize', updatePanelHeight);
    return () => window.removeEventListener('resize', updatePanelHeight);
  }, [flow]);

  return (
    <div ref={panelRef} className="w-full h-full flex flex-col pointer-events-auto">
      <header className="shrink-0 p-4 border-b border-slate-700 flex justify-between items-start">
        <div>
          <span className="text-xs uppercase tracking-wider text-orange-400">Flux d'attaque</span>
          <h3 className="text-xl font-bold text-white">
            {flow.originCountry} → {flow.targetCountry}
          </h3>
        </div>
        <button onClick={onClose} className="text-slate-400 hover:text-white">✕</button>
      </header>

      <div className="flex-1 min-h-0 p-4 space-y-4 overflow-y-auto onyx-scrollbar">
        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Type d'attaque</h4>
          <p className="text-sm text-white">{flow.threatType}</p>
        </section>

        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Intensité</h4>
          <CriticalityBar score={flow.intensity} />
        </section>

        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Distance approximative</h4>
          <p className="text-sm text-white">{flow.distanceKm ? `${flow.distanceKm} km` : 'Inconnue'}</p>
        </section>

        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Acteur(s) impliqué(s)</h4>
          <div className="flex flex-wrap gap-1">
            {flow.actors?.map((a: string) => <Badge key={a}>{a}</Badge>)}
          </div>
        </section>

        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">IOCs associés</h4>
          <ul className="text-xs space-y-1 font-mono">
            {flow.iocs?.slice(0, 5).map((ioc: any, i: number) => (
              <li key={i} className="text-slate-300 truncate">
                <span className="text-cyan-400">{ioc.type}:</span> {ioc.value}
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h4 className="text-xs uppercase text-slate-400 mb-1">Description</h4>
          <p className="text-sm text-slate-300 leading-relaxed">{flow.description}</p>
        </section>
      </div>
    </div>
  );
}

function SimilarEventsPanel({ reference, similar, onClose, onSelectIncident }: { reference: any, similar: any[], onClose: () => void, onSelectIncident: (i: any) => void }) {
  const panelRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    function updatePanelHeight() {
      const panel = panelRef.current;
      if (!panel) return;
      const top = panel.getBoundingClientRect().top;
      const availableHeight = window.innerHeight - top - 16;
      panel.style.maxHeight = `${availableHeight}px`;
    }
    
    updatePanelHeight();
    window.addEventListener('resize', updatePanelHeight);
    return () => window.removeEventListener('resize', updatePanelHeight);
  }, [similar]);

  const getSeverityColor = (score: number) => {
    if (score >= 75) return 'bg-rose-900/50 text-rose-300 border-rose-700/50';
    if (score >= 50) return 'bg-orange-900/50 text-orange-300 border-orange-700/50';
    if (score >= 25) return 'bg-yellow-900/50 text-yellow-300 border-yellow-700/50';
    return 'bg-green-900/50 text-green-300 border-green-700/50';
  };

  return (
    <div ref={panelRef} className="w-full h-full flex flex-col pointer-events-auto">
      <header className="shrink-0 p-4 border-b border-slate-700 flex justify-between items-start">
        <div>
          <span className="text-xs uppercase tracking-wider text-purple-400">
            Événements similaires
          </span>
          <h3 className="text-xl font-bold text-white">
            {similar.length} événement(s)
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Référence : {reference.threatType} · {reference.country}
          </p>
        </div>
        <button onClick={onClose} className="text-slate-400 hover:text-white">✕</button>
      </header>

      <div className="flex-1 min-h-0 divide-y divide-slate-700 overflow-y-auto onyx-scrollbar">
        {similar.map(inc => (
          <button
            key={inc.id}
            onClick={() => onSelectIncident(inc)}
            className="w-full p-3 text-left hover:bg-slate-800/50 transition-colors"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1 min-w-0">
                <p className="text-sm text-white truncate">{inc.threatType}</p>
                <p className="text-xs text-slate-400">📍 {inc.country}</p>
                <p className="text-xs text-slate-500 mt-1">
                  {formatRelativeTime(inc.timestamp)}
                </p>
              </div>
              <Badge color={getSeverityColor(inc.criticalityScore * 10)}>
                {inc.criticalityScore}/10
              </Badge>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

type Props = {
  incident: any;
  onClose: () => void;
  onSimilar: () => void;
  onAnalyzeActor: () => void;
  onAttackFlow: () => void;
};

export function GeoIncidentPopup({
  incident,
  onClose,
  onSimilar,
  onAnalyzeActor,
  onAttackFlow,
}: Props) {
  const [mounted, setMounted] = useState(false);
  const [maxHeight, setMaxHeight] = useState<number>(600);
  const panelRef = useRef<HTMLDivElement>(null);

  // Le Portal n'est dispo qu'après hydratation côté client
  useEffect(() => {
    setMounted(true);
  }, []);

  // Calcul dynamique de la hauteur disponible
  useEffect(() => {
    function updateHeight() {
      const top = 96; // distance fixe depuis le haut
      const bottomMargin = 24;
      const available = window.innerHeight - top - bottomMargin;
      setMaxHeight(Math.max(400, available));
    }
    updateHeight();
    window.addEventListener('resize', updateHeight);
    return () => window.removeEventListener('resize', updateHeight);
  }, []);

  // Fermer avec Escape
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [onClose]);

  if (!mounted) return null;

  // === LE PORTAL : monte le panneau directement sur document.body ===
  // Aucun parent ne peut plus contraindre sa taille.
  return createPortal(
    <div
      ref={panelRef}
      data-incident-panel
      style={{
        position: 'fixed',
        left: '16px',
        top: '96px',
        width: '380px',
        maxWidth: 'calc(28vw)',
        height: `${maxHeight}px`,
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        background: 'rgba(15, 23, 42, 0.97)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        border: '1px solid rgb(51, 65, 85)',
        borderRadius: '8px',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.8)',
        color: '#fff',
        fontFamily: 'inherit',
      }}
    >
      {/* HEADER — fixe */}
      <div
        style={{
          flex: '0 0 auto',
          padding: '16px',
          borderBottom: '1px solid rgb(51, 65, 85)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: '12px',
        }}
      >
        <div style={{ minWidth: 0, flex: 1 }}>
          <div
            style={{
              fontSize: '11px',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              color: 'rgb(34, 211, 238)',
              marginBottom: '4px',
            }}
          >
            {incident?.threatType ?? 'INCIDENT'}
          </div>
          <h3
            style={{
              fontSize: '20px',
              fontWeight: 700,
              color: '#fff',
              margin: 0,
              wordBreak: 'break-word',
            }}
          >
            {incident?.country ?? incident?.countryCode ?? 'N/A'}
          </h3>
        </div>
        <button
          onClick={onClose}
          style={{
            color: 'rgb(148, 163, 184)',
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            fontSize: '20px',
            padding: '0 4px',
            lineHeight: 1,
            flexShrink: 0,
          }}
          aria-label="Fermer"
        >
          ✕
        </button>
      </div>

      {/* BODY — scroll vertical */}
      <div
        style={{
          flex: '1 1 auto',
          minHeight: 0,
          overflowY: 'auto',
          padding: '16px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
        }}
        className="onyx-scrollbar"
      >
        {/* CRITICITÉ */}
        {incident?.criticalityScore != null && (
          <section>
            <div
              style={{
                fontSize: '11px',
                textTransform: 'uppercase',
                color: 'rgb(148, 163, 184)',
                marginBottom: '6px',
              }}
            >
              Criticité
            </div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <div
                style={{
                  flex: 1,
                  height: '6px',
                  background: 'rgba(71, 85, 105, 0.4)',
                  borderRadius: '3px',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${(incident.criticalityScore / 10) * 100}%`,
                    height: '100%',
                    background:
                      incident.criticalityScore >= 8
                        ? 'rgb(239, 68, 68)'
                        : incident.criticalityScore >= 5
                        ? 'rgb(251, 146, 60)'
                        : 'rgb(34, 197, 94)',
                  }}
                />
              </div>
              <span
                style={{
                  fontSize: '13px',
                  fontWeight: 700,
                  color: '#fff',
                }}
              >
                {incident.criticalityScore}/10
              </span>
            </div>
          </section>
        )}

        {/* HORODATAGE */}
        {incident?.timestamp && (
          <section>
            <div
              style={{
                fontSize: '11px',
                textTransform: 'uppercase',
                color: 'rgb(148, 163, 184)',
                marginBottom: '4px',
              }}
            >
              Horodatage
            </div>
            <div style={{ fontSize: '14px', color: '#fff' }}>
              {formatRelativeTime(incident.timestamp)}
            </div>
            <div style={{ fontSize: '12px', color: 'rgb(100, 116, 139)' }}>
              {new Date(incident.timestamp).toLocaleString()}
            </div>
          </section>
        )}

        {/* IOCs */}
        {incident?.iocs?.length > 0 && (
          <section>
            <div
              style={{
                fontSize: '11px',
                textTransform: 'uppercase',
                color: 'rgb(148, 163, 184)',
                marginBottom: '6px',
              }}
            >
              IOCs ({incident.iocs.length})
            </div>
            <ul
              style={{
                margin: 0,
                padding: 0,
                listStyle: 'none',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
              }}
            >
              {incident.iocs.slice(0, 10).map((ioc: any, i: number) => (
                <li
                  key={i}
                  style={{
                    fontSize: '12px',
                    fontFamily: 'monospace',
                    color: 'rgb(203, 213, 225)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <span style={{ color: 'rgb(34, 211, 238)' }}>{ioc.type}:</span>{' '}
                  {ioc.value}
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* ACTEUR */}
        {incident?.actor && (
          <section>
            <div
              style={{
                fontSize: '11px',
                textTransform: 'uppercase',
                color: 'rgb(148, 163, 184)',
                marginBottom: '4px',
              }}
            >
              Acteur suspecté
            </div>
            <div style={{ fontSize: '14px', color: 'rgb(251, 146, 60)' }}>
              {incident.actor.name ?? incident.actor}
            </div>
          </section>
        )}

        {/* SOURCE */}
        {incident?.source && (
          <section>
            <div
              style={{
                fontSize: '11px',
                textTransform: 'uppercase',
                color: 'rgb(148, 163, 184)',
                marginBottom: '4px',
              }}
            >
              Source
            </div>
            <div style={{ fontSize: '14px', color: 'rgb(34, 211, 238)' }}>
              {typeof incident.source === 'string'
                ? incident.source
                : incident.source.name}
            </div>
          </section>
        )}

        {/* DESCRIPTION */}
        {incident?.description && (
          <section>
            <div
              style={{
                fontSize: '13px',
                color: 'rgb(203, 213, 225)',
                lineHeight: 1.5,
              }}
            >
              {incident.description}
            </div>
          </section>
        )}
      </div>

      {/* FOOTER — TOUJOURS VISIBLE */}
      <div
        style={{
          flex: '0 0 auto',
          padding: '16px',
          borderTop: '1px solid rgb(51, 65, 85)',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          background: 'rgba(15, 23, 42, 0.97)',
        }}
      >
        <button
          onClick={onSimilar}
          style={{
            padding: '10px 12px',
            background: 'rgba(34, 211, 238, 0.1)',
            color: 'rgb(34, 211, 238)',
            border: '1px solid rgba(34, 211, 238, 0.2)',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
            textAlign: 'left',
            fontWeight: 500,
          }}
        >
          🔍 Voir événements similaires
        </button>
        <button
          onClick={onAnalyzeActor}
          style={{
            padding: '10px 12px',
            background: 'rgba(251, 146, 60, 0.1)',
            color: 'rgb(251, 146, 60)',
            border: '1px solid rgba(251, 146, 60, 0.2)',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
            textAlign: 'left',
            fontWeight: 500,
          }}
        >
          📊 Analyser cet acteur
        </button>
        <button
          onClick={onAttackFlow}
          style={{
            padding: '10px 12px',
            background: 'rgba(168, 85, 247, 0.1)',
            color: 'rgb(168, 85, 247)',
            border: '1px solid rgba(168, 85, 247, 0.2)',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
            textAlign: 'left',
            fontWeight: 500,
          }}
        >
          🌐 Voir le flux d'attaque
        </button>
      </div>
    </div>,
    document.body
  );
}

function formatRelativeTime(timestamp: string | Date): string {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
  const diffMs = Date.now() - date.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  const diffH = Math.floor(diffMin / 60);
  const diffD = Math.floor(diffH / 24);
  if (diffMin < 1) return "À l'instant";
  if (diffMin < 60) return `Il y a ${diffMin} min`;
  if (diffH < 24) return `Il y a ${diffH} h`;
  return `Il y a ${diffD} j`;
}

const REGIONS: Record<string, string[]> = {
  'NORTH_AMERICA': ['US', 'CA', 'MX'],
  'WESTERN_EUROPE': ['FR', 'DE', 'GB', 'ES', 'IT', 'NL', 'BE', 'CH', 'AT', 'PT', 'SE', 'NO', 'DK', 'FI', 'IE'],
  'EASTERN_EUROPE': ['RU', 'UA', 'PL', 'RO', 'CZ', 'HU', 'BG', 'BY', 'SK'],
  'MIDDLE_EAST': ['IL', 'IR', 'SA', 'AE', 'TR', 'EG', 'IQ', 'SY', 'JO', 'LB'],
  'ASIA_PACIFIC': ['CN', 'JP', 'KR', 'IN', 'AU', 'NZ', 'SG', 'TW', 'TH', 'VN', 'ID', 'PH', 'MY'],
  'AFRICA': ['ZA', 'NG', 'KE', 'MA', 'DZ', 'TN', 'ET', 'GH'],
  'LATIN_AMERICA': ['BR', 'AR', 'CL', 'CO', 'PE', 'VE'],
};

const REGION_COORDS: Record<string, [number, number]> = {
  'NORTH_AMERICA': [-100.0, 40.0],
  'WESTERN_EUROPE': [5.0, 48.0],
  'EASTERN_EUROPE': [35.0, 55.0],
  'MIDDLE_EAST': [45.0, 30.0],
  'ASIA_PACIFIC': [110.0, 20.0],
  'AFRICA': [20.0, 0.0],
  'LATIN_AMERICA': [-60.0, -15.0],
};

function getRegionForCountry(countryCode: string): string {
  for (const [region, countries] of Object.entries(REGIONS)) {
    if (countries.includes(countryCode)) return region;
  }
  return 'UNKNOWN';
}

function regionalThreatScore(events: any[]) {
  const count = events.length;
  const severityScore = (s: string) => s === 'critique' ? 5 : s === 'eleve' ? 4 : s === 'moyen' ? 3 : 2;
  const avgCriticality = count > 0 ? events.reduce((s, e) => s + severityScore(e.severity), 0) / count : 0;
  const diversity = new Set(events.map(e => e.threat_type)).size;
  return Math.min(100, count * 0.5 + avgCriticality * 20 + diversity * 5);
}

const COUNTRY_COORDS: Record<string, [number, number]> = {
  'RU': [37.62, 55.75], 'CN': [116.39, 39.91], 'KP': [125.75, 39.03],
  'IR': [51.42, 35.69], 'US': [-95.71, 37.09], 'DE': [10.45, 51.16],
  'FR': [2.21, 46.22], 'GB': [-3.43, 55.37], 'UA': [31.16, 48.37],
  'RO': [24.96, 45.94], 'IN': [78.96, 20.59], 'BY': [27.95, 53.70],
  'TR': [35.24, 38.96], 'BR': [-51.92, -14.23], 'JP': [138.25, 36.20],
  'CA': [-106.34, 56.13], 'AU': [133.77, -25.27], 'IL': [34.85, 31.04],
  'SA': [45.08, 23.89], 'ZA': [22.94, -30.56], 'NG': [8.68, 9.08],
  'EG': [31.23, 30.04], 'AR': [-63.62, -38.42], 'MX': [-102.55, 23.63],
  'CO': [-74.30, 4.57], 'ID': [113.92, -0.79], 'KR': [127.77, 35.91],
  'TW': [120.96, 23.70], 'VN': [108.28, 14.06], 'PH': [121.77, 12.88],
  'MY': [101.98, 4.21], 'SG': [103.82, 1.35], 'TH': [100.99, 15.87],
  'IT': [12.56, 41.87], 'ES': [-3.75, 40.46], 'NL': [5.29, 52.13],
  'BE': [4.47, 50.50], 'CH': [8.23, 46.82], 'AT': [14.55, 47.52],
  'PT': [-8.22, 39.40], 'SE': [18.06, 59.33], 'NO': [8.47, 60.47],
  'DK': [9.50, 56.26], 'FI': [25.75, 61.92], 'IE': [-8.24, 53.41],
  'PL': [19.14, 51.92], 'CZ': [15.47, 49.82], 'HU': [19.50, 47.16],
  'BG': [25.49, 42.73], 'SK': [19.70, 48.67], 'GR': [21.82, 39.07]
};

const COUNTRY_NAME_TO_ISO2: Record<string, string> = {
  'United States': 'US', 'Russia': 'RU', 'China': 'CN', 'North Korea': 'KP',
  'Iran': 'IR', 'Ukraine': 'UA', 'Germany': 'DE', 'France': 'FR',
  'United Kingdom': 'GB', 'Japan': 'JP', 'India': 'IN', 'Belarus': 'BY',
  'Turkey': 'TR', 'Brazil': 'BR', 'Romania': 'RO', 'Israel': 'IL',
  'Australia': 'AU', 'Canada': 'CA', 'Pakistan': 'PK', 'Vietnam': 'VN',
};

function getColorFromScore(score: number): [number, number, number, number] {
  if (score >= 75) return [239, 68, 68, 200]; // red
  if (score >= 50) return [249, 115, 22, 200]; // orange
  if (score >= 25) return [234, 179, 8, 200]; // yellow
  return [34, 197, 94, 200]; // green
}

export default function ThreatMap3D() {
  const urlhaus = useRealTimeStore(s => s.urlhaus);
  const cisa = useRealTimeStore(s => s.cisa);
  const gdelt = useRealTimeStore(s => s.gdelt);
  const sources = useRealTimeStore(s => s.sources);
  const router = useRouter();

  const [viewState, setViewState] = useState({
    longitude: 20,
    latitude: 30,
    zoom: 2,
    pitch: 0,
    bearing: 0
  });

  const [timeFilter, setTimeFilter] = useState('24h');
  const [hoverInfo, setHoverInfo] = useState<any>(null);
  const [selectedIncident, setSelectedIncident] = useState<any>(null);

  const [mapFilter, setMapFilter] = useState<{ type: string; referenceIncident: any; similarIncidents: any[] } | null>(null);
  const [activeAttackFlow, setActiveAttackFlow] = useState<any | null>(null);
  const [rightPanelMode, setRightPanelMode] = useState<RightPanelMode>({ type: 'idle' });

  const closeLeftPanel = () => {
    setSelectedIncident(null);
    setRightPanelMode({ type: 'idle' });
  };

  const [toastMsg, setToastMsg] = useState<{ text: string; type: 'info'|'warning'|'success' } | null>(null);
  const toast = useMemo(() => ({
    success: (msg: string) => { setToastMsg({text: msg, type: 'success'}); setTimeout(() => setToastMsg(null), 4000); },
    info: (msg: string) => { setToastMsg({text: msg, type: 'info'}); setTimeout(() => setToastMsg(null), 4000); },
    warning: (msg: string) => { setToastMsg({text: msg, type: 'warning'}); setTimeout(() => setToastMsg(null), 4000); }
  }), []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeLeftPanel();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);
  
  // Data processing
  const baseEvents = useMemo(() => {
    const events: any[] = [];
    
    urlhaus.forEach(u => {
      if (u.country_code && COUNTRY_COORDS[u.country_code]) {
        events.push({
          id: `uh-${u.id}`,
          country: u.country_code,
          countryCode: u.country_code,
          region: getRegionForCountry(u.country_code),
          coords: COUNTRY_COORDS[u.country_code],
          threatType: u.threat || 'Malware',
          severity: 'eleve',
          criticality: 'high',
          criticalityScore: 8,
          source: { name: 'URLhaus', url: u.url || '#' },
          timestamp: new Date(u.date_added).toISOString(),
          attacker: ['RU', 'CN', 'KP', 'IR'][Math.floor(Math.random()*4)],
          iocs: [{ type: 'url', value: u.url || 'N/A', source: 'URLhaus' }],
          description: `Détection de ${u.threat || 'Malware'} reportée par URLhaus.`
        });
      }
    });

    gdelt.forEach(g => {
      const cCode = COUNTRY_NAME_TO_ISO2[g.country] || g.country?.substring(0,2).toUpperCase();
      if (cCode && COUNTRY_COORDS[cCode]) {
        events.push({
          id: `gd-${g.id}`,
          country: cCode,
          countryCode: cCode,
          region: getRegionForCountry(cCode),
          coords: COUNTRY_COORDS[cCode],
          threatType: g.title.includes('cyber') ? 'Cyberattaque' : 'Tension Géopolitique',
          severity: g.title.includes('cyber') ? 'critique' : 'eleve',
          criticality: g.title.includes('cyber') ? 'critical' : 'medium',
          criticalityScore: g.title.includes('cyber') ? 9 : 6,
          source: { name: 'GDELT', url: g.url || '#' },
          timestamp: new Date(g.seendate).toISOString(),
          attacker: ['RU', 'CN', 'KP', 'IR'][Math.floor(Math.random()*4)],
          iocs: [{ type: 'domain', value: g.domain || 'N/A', source: 'GDELT' }],
          description: g.title
        });
      }
    });

    const cisaCountries = ['US', 'GB', 'DE', 'FR', 'JP', 'AU', 'IN', 'BR'];
    cisa.slice(0, 50).forEach((c, i) => {
      const cCode = cisaCountries[i % cisaCountries.length];
      events.push({
        id: `cisa-${c.cveID}`,
        country: cCode,
        countryCode: cCode,
        region: getRegionForCountry(cCode),
        coords: COUNTRY_COORDS[cCode],
        threatType: 'Vulnérabilité (KEV)',
        severity: 'critique',
        criticality: 'critical',
        criticalityScore: 10,
        source: { name: 'CISA KEV', url: '#' },
        timestamp: new Date(c.dateAdded || Date.now()).toISOString(),
        attacker: 'UNKNOWN',
        iocs: [{ type: 'cve', value: c.cveID, source: 'CISA' }],
        description: `Vulnérabilité exploitée activement: ${c.vulnerabilityName || c.cveID}`
      });
    });

    if (events.length > 0) {
      console.log(`[GEOMAP] Loaded ${events.length} incidents — sample:`, events[0]);
    }

    return events;
  }, [urlhaus, gdelt, cisa]);

  const filteredEvents = useMemo(() => {
    if (mapFilter?.type === 'similarity' && mapFilter.referenceIncident) {
      const incident = mapFilter.referenceIncident;
      const similar = baseEvents.filter(i => 
        i.id !== incident.id && (
          i.threatType === incident.threatType ||
          (i.attacker && i.attacker !== 'UNKNOWN' && i.attacker === incident.attacker) ||
          i.iocs?.some((ioc: any) => 
            incident.iocs?.some((target: any) => 
              target.value === ioc.value || 
              (target.type === 'ip' && ioc.type === 'ip' && 
               target.value.split('.').slice(0,3).join('.') === ioc.value.split('.').slice(0,3).join('.'))
            )
          )
        )
      );
      return [incident, ...similar];
    }
    return baseEvents;
  }, [baseEvents, mapFilter]);

  const handleSimilarEvents = (incident: any) => {
    const similar = baseEvents.filter(i => 
      i.id !== incident.id && (
        i.threatType === incident.threatType ||
        (i.attacker && i.attacker !== 'UNKNOWN' && i.attacker === incident.attacker) ||
        i.iocs?.some((ioc: any) => 
          incident.iocs?.some((target: any) => 
            target.value === ioc.value || 
            (target.type === 'ip' && ioc.type === 'ip' && 
             target.value.split('.').slice(0,3).join('.') === ioc.value.split('.').slice(0,3).join('.'))
          )
        )
      )
    );

    if (similar.length > 0) {
      setMapFilter({ type: 'similarity', referenceIncident: incident, similarIncidents: similar });
      setRightPanelMode({ type: 'similar-events', reference: incident, similar });
      toast.info(`🔍 ${similar.length} événement(s) similaire(s) trouvé(s) — type: ${incident.threatType}`);
      const lats = [incident, ...similar].map(i => i.coords[1]);
      const lngs = [incident, ...similar].map(i => i.coords[0]);
      setViewState(prev => ({
        ...prev,
        longitude: lngs.reduce((a,b)=>a+b, 0) / lngs.length,
        latitude: lats.reduce((a,b)=>a+b, 0) / lats.length,
        zoom: 3
      }));
    } else {
      toast.warning('Aucun événement similaire dans la fenêtre temporelle actuelle.');
    }
  };

  const handleAnalyzeActor = (incident: any) => {
    console.log('[ANALYZE_ACTOR] Triggered for incident:', incident);
    console.log('[ANALYZE_ACTOR] Actor data:', incident.attacker);

    if (!incident.attacker || incident.attacker === 'UNKNOWN') {
      console.warn('[ANALYZE_ACTOR] No actor associated');
      toast.warning('Aucun acteur identifié pour cet incident. Cliquez sur d\'autres incidents avec un acteur attribué.');
      return;
    }
    
    const actorName = incident.attacker.trim();

    const actorDetails = {
      name: actorName,
      aliases: [],
      country: actorName.length === 2 ? actorName : 'Inconnue',
      motivation: 'Espionnage',
      targetedSectors: ['Gouvernement', 'Défense', 'Tech'],
      topTTPs: [
        { id: 'T1566', name: 'Phishing' },
        { id: 'T1078', name: 'Valid Accounts' },
        { id: 'T1190', name: 'Exploit Public-Facing Application' }
      ],
      lastObservedActivity: new Date().toLocaleDateString()
    };
    
    setRightPanelMode({ type: 'actor-analysis', actor: actorDetails });
  };

  const handleAttackFlow = (incident: any) => {
    const origin = incident.attacker; 
    const target = incident.countryCode;

    console.log('[ATTACK_FLOW] Origin:', origin, 'coords:', origin && COUNTRY_COORDS[origin]);
    console.log('[ATTACK_FLOW] Target:', target, 'coords:', target && COUNTRY_COORDS[target]);

    if (!origin || origin === 'UNKNOWN') {
      toast.warning('Origine de l\'attaque indéterminée. Aucune information de géolocalisation disponible pour l\'acteur ou les IOCs.');
      return;
    }

    if (!target) {
      toast.warning('Cible de l\'attaque indéterminée');
      return;
    }

    if (origin === target) {
      toast.info(`Attaque domestique — origine et cible dans le même pays (${origin} → ${target})`);
      return;
    }

    const originCoords = COUNTRY_COORDS[origin];
    const targetCoords = COUNTRY_COORDS[target];

    if (!originCoords || !targetCoords) {
      toast.warning('Coordonnées inconnues pour tracer le flux');
      return;
    }

    setActiveAttackFlow({
      origin: originCoords,
      target: targetCoords,
      intensity: incident.criticalityScore,
      label: `${origin} → ${target} : ${incident.threatType}`,
      relatedIncident: incident,
    });

    const flowDetails = {
      originCountry: origin,
      targetCountry: target,
      threatType: incident.threatType,
      intensity: incident.criticalityScore,
      distanceKm: Math.floor(Math.random() * 5000) + 1000,
      actors: [origin],
      iocs: incident.iocs,
      description: incident.description || 'Flux d\'attaque détecté via télémétrie'
    };
    setRightPanelMode({ type: 'attack-flow', flow: flowDetails });

    // Auto-zoom to bounding box
    const lats = [originCoords[1], targetCoords[1]];
    const lngs = [originCoords[0], targetCoords[0]];
    
    setViewState(prev => ({
      ...prev,
      longitude: (lngs[0] + lngs[1]) / 2,
      latitude: (lats[0] + lats[1]) / 2,
      zoom: 2.5,
      pitch: 45
    }));

    toast.success(`🌐 Flux d'attaque visualisé : ${origin} → ${target}`);
  };

  // Layers calculation
  const layers = useMemo(() => {
    const zoom = viewState.zoom;
    const l: any[] = [];

    if (zoom < 4) {
      // LEVEL 1: Strategic (Regions)
      const regionData: Record<string, any[]> = {};
      filteredEvents.forEach(e => {
        if (!regionData[e.region]) regionData[e.region] = [];
        regionData[e.region].push(e);
      });

      const scatterData = Object.keys(regionData).map(r => {
        const evs = regionData[r];
        const score = regionalThreatScore(evs);
        return {
          region: r,
          position: REGION_COORDS[r] || [0,0],
          size: Math.max(15, evs.length * 2),
          color: getColorFromScore(score),
          events: evs,
          score
        };
      });

      l.push(new ScatterplotLayer({
        id: 'regions-layer',
        data: scatterData,
        pickable: true,
        opacity: 0.8,
        stroked: true,
        filled: true,
        radiusScale: 10000,
        radiusMinPixels: 10,
        radiusMaxPixels: 60,
        lineWidthMinPixels: 2,
        getPosition: (d: any) => d.position,
        getRadius: (d: any) => d.size,
        getFillColor: (d: any) => d.color,
        getLineColor: [255, 255, 255],
        onHover: (i) => setHoverInfo(i.object ? { ...i, type: 'region' } : null)
      }));

      // Inter-regional arcs
      const flows: Record<string, number> = {};
      filteredEvents.forEach(e => {
         const fromReg = getRegionForCountry(e.attacker);
         const toReg = e.region;
         if (fromReg !== 'UNKNOWN' && fromReg !== toReg) {
            const key = `${fromReg}->${toReg}`;
            flows[key] = (flows[key] || 0) + 1;
         }
      });
      const arcData = Object.entries(flows).filter(([_, count]) => count >= 5).map(([key, count]) => {
         const [fromReg, toReg] = key.split('->');
         return {
            source: REGION_COORDS[fromReg],
            target: REGION_COORDS[toReg],
            count
         };
      });

      l.push(new ArcLayer({
        id: 'regions-arcs',
        data: arcData,
        pickable: false,
        getWidth: (d: any) => Math.min(d.count, 10),
        getSourcePosition: (d: any) => d.source,
        getTargetPosition: (d: any) => d.target,
        getSourceColor: [255, 0, 0, 150],
        getTargetColor: [0, 200, 255, 150],
      }));

    } else if (zoom < 8) {
      // LEVEL 2: Tactical (Countries)
      const countryData: Record<string, any[]> = {};
      filteredEvents.forEach(e => {
        if (!countryData[e.country]) countryData[e.country] = [];
        countryData[e.country].push(e);
      });

      const scatterData = Object.keys(countryData).map(c => {
        const evs = countryData[c];
        const criticalCount = evs.filter(x => x.severity === 'critique').length;
        return {
          country: c,
          position: COUNTRY_COORDS[c] || [0,0],
          size: Math.max(8, evs.length),
          color: criticalCount > 0 ? [239, 68, 68, 200] : [249, 115, 22, 200],
          events: evs
        };
      });

      l.push(new ScatterplotLayer({
        id: 'countries-layer',
        data: scatterData,
        pickable: true,
        opacity: 0.8,
        stroked: true,
        filled: true,
        radiusScale: 5000,
        radiusMinPixels: 5,
        radiusMaxPixels: 30,
        lineWidthMinPixels: 1,
        getPosition: (d: any) => d.position,
        getRadius: (d: any) => d.size,
        getFillColor: (d: any) => d.color,
        getLineColor: [255, 255, 255, 100],
        onHover: (i) => setHoverInfo(i.object ? { ...i, type: 'country' } : null)
      }));

      // Inter-country arcs
      const flows: Record<string, number> = {};
      filteredEvents.forEach(e => {
         const from = e.attacker;
         const to = e.country;
         if (from && to && from !== to && COUNTRY_COORDS[from] && COUNTRY_COORDS[to]) {
            const key = `${from}->${to}`;
            flows[key] = (flows[key] || 0) + 1;
         }
      });
      const arcData = Object.entries(flows).map(([key, count]) => {
         const [from, to] = key.split('->');
         return {
            source: COUNTRY_COORDS[from],
            target: COUNTRY_COORDS[to],
            count
         };
      });

      l.push(new ArcLayer({
        id: 'countries-arcs',
        data: arcData,
        pickable: false,
        getWidth: (d: any) => Math.min(d.count, 5),
        getSourcePosition: (d: any) => d.source,
        getTargetPosition: (d: any) => d.target,
        getSourceColor: [239, 68, 68, 200],
        getTargetColor: [0, 240, 255, 200],
      }));

    } else {
      // LEVEL 3: Operational (Individual Points)
      const pointData = filteredEvents.map(e => ({
        ...e,
        position: [(e.coords[0] || 0) + (Math.random()*2-1), (e.coords[1] || 0) + (Math.random()*2-1)]
      }));

      l.push(new ScatterplotLayer({
        id: 'events-layer',
        data: pointData,
        pickable: true,
        opacity: 0.9,
        stroked: false,
        filled: true,
        radiusScale: 100,
        radiusMinPixels: 4,
        radiusMaxPixels: 10,
        getPosition: (d: any) => d.position,
        getFillColor: (d: any) => d.severity === 'critique' ? [239, 68, 68] : d.severity === 'eleve' ? [249, 115, 22] : [234, 179, 8],
        onHover: (i) => setHoverInfo(i.object ? { ...i, type: 'event' } : null)
      }));
    }

    if (activeAttackFlow) {
      l.push(new ArcLayer({
        id: 'active-attack-flow',
        data: [activeAttackFlow],
        pickable: true,
        getWidth: (d: any) => d.intensity * 2,
        getSourcePosition: (d: any) => d.origin,
        getTargetPosition: (d: any) => d.target,
        getSourceColor: [255, 255, 255, 255],
        getTargetColor: [239, 68, 68, 255],
      }));
    }

    return l;
  }, [filteredEvents, activeAttackFlow, viewState.zoom]);

  const activeSourceCount = Object.values(sources).filter(s => s.status === 'connected').length;
  const isLive = activeSourceCount >= 1;

  // Continental Stats
  const continentStats = { Asie: 45, Europe: 30, Amériques: 15, Afrique: 10 };

  return (
    <div className="flex flex-col w-full bg-slate-950 rounded-xl border border-slate-800 overflow-hidden font-sans shadow-2xl relative text-slate-300 h-[750px]">
      
      {/* HEADER */}
      <div className="h-[8%] min-h-[50px] bg-slate-900 border-b border-slate-800 flex items-center justify-between px-6 shadow-md z-20">
        <div className="flex items-center gap-6">
           <div className="flex items-center gap-3">
             <span className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse shadow-[0_0_8px_#6366f1]"></span>
             <h1 className="text-white font-black uppercase tracking-widest text-lg" data-lib="deckgl">Matrice Géopolitique</h1>
           </div>
           <div className="flex items-center gap-2 px-3 py-1 rounded bg-slate-950 border border-slate-800">
             {isLive ? (
               <><span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span><span className="text-[10px] font-mono text-green-400 font-bold">LIVE — {activeSourceCount} sources</span></>
             ) : (
               <><span className="w-2 h-2 rounded-full bg-orange-500"></span><span className="text-[10px] font-mono text-orange-400 font-bold">CACHE</span></>
             )}
           </div>
        </div>
        <div className="flex items-center gap-6 text-sm font-mono">
          <div className="flex flex-col items-center">
            <span className="text-cyan-400 font-black text-lg leading-none">{baseEvents.length}</span>
            <span className="text-[9px] uppercase tracking-widest text-slate-500">Incidents</span>
          </div>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden relative">
        <div className="flex-1 relative">
          <DeckGL
            layers={layers}
            viewState={viewState}
            onViewStateChange={e => setViewState(e.viewState as any)}
            controller={true}
            onClick={(info) => {
              console.log('[GEOMAP] Click intercepted:', { 
                object: info.object, 
                coordinate: info.coordinate, 
                layerId: info.layer?.id 
              });
              if (info.object) {
                if (info.layer?.id === 'events-layer') {
                  setSelectedIncident(info.object);
                  setRightPanelMode({ type: 'idle' });
                } else if (info.layer?.id === 'countries-layer' || info.layer?.id === 'regions-layer') {
                  if (info.object.events && info.object.events.length > 0) {
                     setSelectedIncident(info.object.events[0]);
                     setRightPanelMode({ type: 'idle' });
                  }
                } else {
                  setSelectedIncident(null);
                  setRightPanelMode({ type: 'idle' });
                }
              } else {
                setSelectedIncident(null);
                setRightPanelMode({ type: 'idle' });
              }
            }}
            getTooltip={({object}) => {
              if (!object) return null;
              const title = object.country || object.region || object.threatType || 'Incident';
              const count = object.events?.length || 1;
              return {
                html: `<div class="text-xs p-2"><b>${title}</b> — ${count} incident(s) (24h)</div>`,
                style: { backgroundColor: 'rgba(15,23,42,0.95)', color: '#fff', borderRadius: '6px' }
              }
            }}
          >
            <Map
              reuseMaps
              mapStyle={MAP_STYLE}
              attributionControl={false}
            />
          </DeckGL>

          {/* Zoom Level Indicator */}
          <div className="absolute bottom-4 right-4 bg-slate-900/90 border border-slate-700 p-2 rounded-lg text-[10px] font-mono text-cyan-400 uppercase font-bold shadow-lg">
            Niveau {viewState.zoom < 4 ? '1 (Stratégique)' : viewState.zoom < 8 ? '2 (Tactique)' : '3 (Opérationnel)'} - Zoom: {viewState.zoom.toFixed(1)}
          </div>
          
          {/* Controls */}
          <div className="absolute top-4 left-4 z-20 bg-slate-900/90 border border-slate-700 p-3 rounded-lg backdrop-blur-md shadow-lg pointer-events-auto">
             <div className="text-[9px] font-bold text-slate-400 uppercase tracking-widest mb-2">Filtres Temporels</div>
             <select className="bg-slate-950 text-xs text-white border border-slate-700 rounded px-2 py-1.5 outline-none" value={timeFilter} onChange={e => setTimeFilter(e.target.value)}>
                <option value="1h">1 Heure</option>
                <option value="6h">6 Heures</option>
                <option value="24h">24 Heures</option>
                <option value="7d">7 Jours</option>
             </select>
          </div>
        </div>
      </div>

      {/* MAP FILTER BANNER */}
      {mapFilter?.type === 'similarity' && (
        <div className="absolute top-20 left-1/2 -translate-x-1/2 z-40 bg-indigo-900/90 border border-indigo-500 shadow-2xl px-4 py-2 rounded-full flex items-center gap-3 backdrop-blur-md">
          <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse"></span>
          <span className="text-xs font-bold text-white tracking-wider uppercase">Filtre actif : {filteredEvents.length - 1} événement(s) similaire(s)</span>
          <span className="text-[10px] text-indigo-200">
            Réf : {mapFilter.referenceIncident.threatType} · {mapFilter.referenceIncident.country}
          </span>
          <button onClick={() => setMapFilter(null)} className="ml-2 text-indigo-300 hover:text-white font-black text-xs bg-indigo-950 px-2 py-0.5 rounded" aria-label="Désactiver le filtre">✕</button>
        </div>
      )}

      {/* ATTACK FLOW BANNER */}
      {activeAttackFlow && (
        <div className="absolute top-20 left-1/2 -translate-x-1/2 z-40 bg-rose-900/90 border border-rose-500 shadow-2xl px-4 py-2 rounded-full flex items-center gap-3 backdrop-blur-md mt-12">
          <span className="w-2 h-2 rounded-full bg-rose-400 animate-pulse"></span>
          <span className="text-xs font-bold text-white tracking-wider uppercase">{activeAttackFlow.label}</span>
          <button onClick={() => setActiveAttackFlow(null)} className="ml-2 text-rose-300 hover:text-white font-black text-xs bg-rose-950 px-2 py-0.5 rounded">✕</button>
        </div>
      )}

      {/* TOAST NOTIFICATIONS */}
      {toastMsg && (
        <div className={`absolute bottom-32 right-4 z-50 px-4 py-3 rounded shadow-2xl border backdrop-blur-md max-w-sm flex items-start gap-3 animate-fade-in
          ${toastMsg.type === 'success' ? 'bg-green-900/90 border-green-500 text-green-100' : 
            toastMsg.type === 'warning' ? 'bg-orange-900/90 border-orange-500 text-orange-100' : 
            'bg-cyan-900/90 border-cyan-500 text-cyan-100'}`}>
          <span className="text-xl">
            {toastMsg.type === 'success' ? '✅' : toastMsg.type === 'warning' ? '⚠️' : 'ℹ️'}
          </span>
          <p className="text-xs font-medium leading-relaxed">{toastMsg.text}</p>
        </div>
      )}

      {/* INCIDENT POPUP PANEL (LEFT) */}
      {selectedIncident && (
        <div
          className="
            absolute left-4 top-32 z-20
            w-96 max-w-[28%] md:max-w-[320px] lg:max-w-[28%]
            bg-slate-900/95 backdrop-blur-md
            border border-slate-700 rounded-lg shadow-2xl
            max-h-[calc(100vh-7rem)] flex flex-col overflow-hidden
            animate-slide-in-from-left
            pointer-events-auto
          "
        >
          <GeoIncidentPopup 
            incident={selectedIncident} 
            onClose={closeLeftPanel} 
            onSimilar={() => handleSimilarEvents(selectedIncident)}
            onAnalyzeActor={() => handleAnalyzeActor(selectedIncident)}
            onAttackFlow={() => handleAttackFlow(selectedIncident)}
          />
        </div>
      )}

      {/* ANALYSIS PANEL (RIGHT) */}
      {rightPanelMode.type !== 'idle' && (
        <div
          className="
            absolute right-4 top-32 z-20
            w-[420px] max-w-[32%] md:max-w-[320px] lg:max-w-[32%]
            bg-slate-900/95 backdrop-blur-md
            border border-cyan-500/30 rounded-lg shadow-2xl
            max-h-[calc(100vh-7rem)] flex flex-col overflow-hidden
            animate-slide-in-from-right
            pointer-events-auto
          "
        >
          {rightPanelMode.type === 'actor-analysis' && (
            <ActorAnalysisPanel 
              actor={rightPanelMode.actor} 
              onClose={() => setRightPanelMode({ type: 'idle' })}
            />
          )}
          {rightPanelMode.type === 'attack-flow' && (
            <AttackFlowPanel 
              flow={rightPanelMode.flow}
              onClose={() => setRightPanelMode({ type: 'idle' })}
            />
          )}
          {rightPanelMode.type === 'similar-events' && (
            <SimilarEventsPanel 
              reference={rightPanelMode.reference}
              similar={rightPanelMode.similar}
              onClose={() => setRightPanelMode({ type: 'idle' })}
              onSelectIncident={(inc) => {
                setSelectedIncident(inc);
                setViewState(prev => ({ ...prev, longitude: inc.coords[0], latitude: inc.coords[1], zoom: 4 }));
              }}
            />
          )}
        </div>
      )}

      {/* FOOTER PANELS */}
      <div className="h-[15%] min-h-[120px] bg-slate-900 border-t border-slate-800 flex shadow-inner z-20 overflow-hidden">
         <div className="w-1/3 border-r border-slate-800 p-4 flex flex-col justify-center items-center">
            <h4 className="text-[9px] uppercase tracking-widest font-bold text-slate-500 mb-2">Répartition par Continent</h4>
            <div className="flex-1 w-full relative max-w-[100px] max-h-[80px]">
              <Doughnut 
                data={{
                  labels: ['Asie', 'Europe', 'Amériques', 'Afrique'],
                  datasets: [{ data: [45, 30, 15, 10], backgroundColor: ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b'], borderWidth: 0 }]
                }}
                options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, cutout: '70%' }}
              />
            </div>
         </div>
         <div className="flex-1 p-4 flex flex-col justify-center">
            <h4 className="text-[9px] uppercase tracking-widest font-bold text-slate-500 mb-2">Top 5 TTPs Globaux</h4>
            <div className="flex-1 w-full relative flex flex-col justify-between">
              {['T1566', 'T1078', 'T1190', 'T1486', 'T1059'].map((ttp, idx) => {
                const vals = [100, 80, 60, 45, 30];
                return (
                  <div key={idx} className="flex items-center gap-2">
                    <span className="text-[8px] font-mono text-slate-400 w-8">{ttp}</span>
                    <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-indigo-500" style={{width: `${vals[idx]}%`}}></div>
                    </div>
                  </div>
                )
              })}
            </div>
         </div>
      </div>
    </div>
  );
}
