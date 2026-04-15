'use client';

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import * as d3 from 'd3';
import { useOnyxStore } from '@/lib/store';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// ─── TYPES ──────────────────────────────────────────────────────────────────

interface HeatmapData { tactic: string; technique: string; intensity: number; last_seen: string; }
interface TimelineEvent { id: string; date: string; phase: string; description: string; severity: string; icon?: string; }
interface GraphNode { id: string; group: number; name: string; type: string; x?: number; y?: number; radius?: number; }
interface GraphLink { source: string | GraphNode; target: string | GraphNode; value: number; }

interface ThreatActor {
  id: string;
  name: string;
  description: string;
  target: string;
  techniques: string[];
  tools: string[];
  severity: string;
  aliases: string[];
  status: string;
  live_iocs: number;
  graph_data?: { nodes: GraphNode[]; links: GraphLink[] };
  heatmap_data?: HeatmapData[];
  timeline_events?: TimelineEvent[];
}

// ─── HELPER: COLOR PALETTES ──────────────────────────────────────────────────

const typeColors: Record<string, string> = { actor: '#ff3b5c', tool: '#00eeff', ttp: '#a855f7', ioc: '#f59e0b', default: '#64748b' };
const typeLabels: Record<string, string> = { actor: 'Threat Actor', tool: 'Malware / Tool', ttp: 'MITRE Technique', ioc: 'IOC Indicator' };
const typeIcons: Record<string, string> = { actor: '☠', tool: '⬡', ttp: '⚔', ioc: '◎' };
const sevColor = (s: string) => ({ critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }[s] || '#6b7280');

// ─── HELPER: MITRE Technique ID to human-readable tactical mapping ──────────
const TECHNIQUE_METADATA: Record<string, { name: string; tactic: string }> = {
  'T1059': { name: 'Command & Scripting Interpreter', tactic: 'Execution' },
  'T1059.001': { name: 'PowerShell', tactic: 'Execution' },
  'T1071': { name: 'Application Layer Protocol', tactic: 'Command and Control' },
  'T1071.001': { name: 'Web Protocols', tactic: 'Command and Control' },
  'T1078': { name: 'Valid Accounts', tactic: 'Persistence' },
  'T1110': { name: 'Brute Force', tactic: 'Credential Access' },
  'T1190': { name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  'T1486': { name: 'Data Encrypted for Impact', tactic: 'Impact' },
  'T1566': { name: 'Phishing', tactic: 'Initial Access' },
  'T1568': { name: 'Dynamic Resolution', tactic: 'Command and Control' },
  'T1598': { name: 'Phishing for Information', tactic: 'Reconnaissance' },
  'T1621': { name: 'Multi-Factor Auth Request', tactic: 'Credential Access' },
  'T1560': { name: 'Archive Collected Data', tactic: 'Collection' },
  'T1053': { name: 'Scheduled Task/Job', tactic: 'Execution' },
  'T1047': { name: 'Windows Management Instrumentation', tactic: 'Execution' },
  'T1102': { name: 'Web Service', tactic: 'Command and Control' },
  'T1548': { name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation' },
  'T1003': { name: 'OS Credential Dumping', tactic: 'Credential Access' },
  'T1072': { name: 'Software Deployment Tools', tactic: 'Lateral Movement' },
  'T1210': { name: 'Exploitation of Remote Services', tactic: 'Lateral Movement' },
  'T1027': { name: 'Obfuscated Files or Information', tactic: 'Defense Evasion' },
  'T1105': { name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
  'T1055': { name: 'Process Injection', tactic: 'Defense Evasion' },
  'T1036': { name: 'Masquerading', tactic: 'Defense Evasion' },
  'T1569': { name: 'System Services', tactic: 'Execution' },
  'T1082': { name: 'System Information Discovery', tactic: 'Discovery' },
  'T1083': { name: 'File and Directory Discovery', tactic: 'Discovery' },
  'T1018': { name: 'Remote System Discovery', tactic: 'Discovery' },
  'T1048': { name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' },
  'T1041': { name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  'T1573': { name: 'Encrypted Channel', tactic: 'Command and Control' },
  'T1574': { name: 'Hijack Execution Flow', tactic: 'Persistence' },
  'T1547': { name: 'Boot or Logon Autostart Execution', tactic: 'Persistence' },
  'T1219': { name: 'Remote Access Software', tactic: 'Command and Control' },
};

// ─── SECTION: Targeted Industries Mapping ───────────────────────────────────
const ACTOR_INDUSTRIES: Record<string, string[]> = {
  'APT29': ['Government & Defense', 'Energy', 'Healthcare', 'Think Tanks', 'Diplomatic Missions'],
  'Volt Typhoon': ['Critical Infrastructure', 'Telecommunications', 'ISPs', 'Maritime', 'Government'],
  'Lazarus Group': ['Financial Services', 'Cryptocurrency', 'Defense', 'Media & Entertainment', 'Aerospace'],
  'Scattered Spider': ['Telecommunications', 'Technology', 'Cloud Services', 'Gaming', 'Finance'],
  'FIN7': ['Retail & POS', 'Hospitality', 'Financial Services', 'Restaurant Chains'],
  'APT41': ['Healthcare', 'Telecommunications', 'Technology', 'Gaming', 'Higher Education'],
  'Sandworm Team': ['Energy & Utilities', 'Government', 'Transportation', 'Media', 'Industrial Control Systems'],
  'Turla': ['Government', 'Military', 'Research Institutions', 'Embassies', 'Aerospace'],
  'Equation': ['Government', 'Military', 'Telecommunications', 'Energy', 'Research'],
  'Gorgon Group': ['Government', 'Military', 'Technology'],
  'Mustang Panda': ['Government', 'Non-Profits', 'Religious Organizations', 'Think Tanks'],
  'OilRig': ['Government', 'Financial', 'Energy', 'Telecommunications', 'Chemical'],
};

// ─── SUB 1: ENRICHED PROFILE VIEW ──────────────────────────────────────────

const ProfileView = React.memo(({ actor }: { actor: ThreatActor | null }) => {
  if (!actor) return <div className="onyx-card h-[180px] flex items-center justify-center text-gray-500 font-mono">Select an Adversary</div>;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex justify-between items-start">
        <div className="flex items-center gap-3">
           <h2 className="text-2xl font-bold text-white">{actor.name}</h2>
           <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase" style={{ borderColor: sevColor(actor.severity), color: sevColor(actor.severity) }}>{actor.severity}</span>
           {actor.status === 'Active Now' && (
             <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-900/30 border border-red-500/50 text-red-400 animate-pulse">● ACTIVE</span>
           )}
        </div>
      </div>
      <div className="text-xs text-gray-400 font-mono leading-relaxed">{actor.description}</div>
      <div>
        <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-1">Known Aliases</div>
        <div className="flex flex-wrap gap-1.5">
          {actor.aliases?.length > 0 ? actor.aliases.map(a => (
            <span key={a} className="text-[10px] px-2 py-0.5 bg-purple-900/20 border border-purple-500/30 rounded text-purple-300 font-mono">{a}</span>
          )) : (
            <span className="text-[10px] text-gray-600 font-mono">No known aliases</span>
          )}
        </div>
      </div>
    </div>
  );
});
ProfileView.displayName = 'ProfileView';

// ─── NEW: VICTIM VIEW ────────────────────────────────────────────────────────
const VictimView = React.memo(({ actor }: { actor: ThreatActor | null }) => {
  if (!actor) return null;
  const industries = ACTOR_INDUSTRIES[actor.name] || ['Unclassified Sectors'];
  
  // Extract simple proxy for countries from target string if any, else generic
  const targetStr = actor.target || "";
  let countries = ["Global", "Regional Actors"];
  if (targetStr.includes("United States") || actor.name.includes("29")) countries = ["United States", "European Union"];
  if (actor.name.includes("Volt")) countries = ["United States", "Taiwan", "Pacific RIM"];
  if (actor.name.includes("Lazarus")) countries = ["South Korea", "Japan", "United States"];
  if (actor.name.includes("Scattered")) countries = ["United States", "United Kingdom"];

  return (
    <div className="flex flex-col gap-4">
      <div>
        <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-2 flex items-center gap-2"><span className="text-red-500">❖</span> Targeted Sectors</div>
        <div className="flex flex-wrap gap-1.5">
          {industries.map(ind => (
            <span key={ind} className="text-[10px] px-2 py-0.5 bg-red-900/20 border border-red-500/30 rounded text-red-300 font-mono">{ind}</span>
          ))}
        </div>
      </div>
      <div>
        <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-2 flex items-center gap-2"><span className="text-blue-500">❖</span> Primary Target Regions</div>
        <div className="flex flex-wrap gap-1.5">
          {countries.map(c => (
             <span key={c} className="text-[10px] px-2 py-0.5 bg-blue-900/20 border border-blue-500/30 rounded text-blue-300 font-mono">{c}</span>
          ))}
        </div>
      </div>
    </div>
  );
});
VictimView.displayName = 'VictimView';



// ─── SUB 2: TOOLS & MALWARE ARSENAL ─────────────────────────────────────────

const ArsenalView = React.memo(({ actor }: { actor: ThreatActor | null }) => {
  if (!actor) return null;
  const tools = actor.tools || [];
  const TOOL_META: Record<string, { type: string; color: string }> = {
    'Cobalt Strike': { type: 'C2 Framework', color: '#ef4444' },
    'Mimikatz': { type: 'Credential Harvester', color: '#f59e0b' },
    'SUNBURST': { type: 'Backdoor', color: '#ef4444' },
    'GRIFFON': { type: 'Backdoor', color: '#ef4444' },
    'HOPLIGHT': { type: 'RAT', color: '#f97316' },
    'KV-Botnet': { type: 'Botnet', color: '#a855f7' },
    'LockBit 3.0': { type: 'Ransomware', color: '#ef4444' },
    'Custom RAT': { type: 'RAT', color: '#f97316' },
    'InfoStealer': { type: 'Stealer', color: '#eab308' },
    'PowerShell': { type: 'LOLBin', color: '#00eeff' },
    'certutil.exe': { type: 'LOLBin', color: '#00eeff' },
    'WellMess': { type: 'RAT', color: '#f97316' },
    'WellMail': { type: 'Backdoor', color: '#ef4444' },
    'ShadowPad': { type: 'Modular Backdoor', color: '#ef4444' },
    'PlugX': { type: 'RAT', color: '#f97316' },
    'njRAT': { type: 'RAT', color: '#f97316' },
    'Emotet': { type: 'Loader', color: '#a855f7' },
    'BlackEnergy': { type: 'ICS Malware', color: '#ef4444' },
    'Industroyer': { type: 'ICS Malware', color: '#ef4444' },
    'NotPetya': { type: 'Wiper', color: '#ef4444' },
    'Olympic Destroyer': { type: 'Wiper', color: '#ef4444' },
  };

  // Group tools by type
  const groupedTools: Record<string, {name: string, color: string}[]> = {};
  for (const t of tools) {
     const toolName = typeof t === 'string' ? t : (t as any).name;
     if (!toolName) continue;
     const meta = TOOL_META[toolName] || { type: 'Unknown Utility', color: '#6b7280' };
     if (!groupedTools[meta.type]) groupedTools[meta.type] = [];
     groupedTools[meta.type].push({ name: toolName, color: meta.color });
  }

  return (
    <div className="flex flex-col gap-2">
      <h3 className="text-xs font-bold uppercase text-gray-400 mb-4 tracking-wider flex items-center gap-2">
        <span style={{ color: '#00eeff' }}>⬡</span> Malware & Tools Arsenal
        <span className="text-[10px] font-normal text-gray-600">({tools.length} identified)</span>
      </h3>
      {tools.length > 0 ? (
        <div className="flex flex-col gap-4">
          {Object.entries(groupedTools).map(([type, items]) => (
             <div key={type} className="bg-[#05080f] p-3 rounded border border-gray-800/60">
                <div className="text-[9px] uppercase tracking-[0.15em] font-bold text-gray-500 mb-2 border-b border-gray-800 pb-1">{type}</div>
                <div className="flex flex-wrap gap-2">
                   {items.map(item => (
                     <div key={item.name} className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#0a0f1a] border border-gray-700/50 hover:border-gray-500 transition-colors">
                        <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: item.color, boxShadow: `0 0 4px ${item.color}80` }} />
                        <span className="text-xs font-bold text-gray-200">{item.name}</span>
                     </div>
                   ))}
                </div>
             </div>
          ))}
        </div>
      ) : (
        <div className="text-xs text-gray-600 font-mono text-center py-4 bg-[#0a0f1a] rounded border border-gray-800/30">No tooling data available from active ingestion pipeline</div>
      )}
    </div>
  );
});
ArsenalView.displayName = 'ArsenalView';


// ─── SUB 3: DETAILED TTP VIEW WITH PEDAGOGICAL PANELS ──────────────────────

interface PedagogyData {
  name: string;
  explanation: string;
  impact: string;
  example: string;
  mitigation: string;
}

const TechniquePedagogyPanel = React.memo(({ techniqueId, tacticColor, onClose }: { 
  techniqueId: string; tacticColor: string; onClose: () => void;
}) => {
  const [data, setData] = useState<PedagogyData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch(`${API}/api/v1/dashboard/mitre-pedagogy/${techniqueId}`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [techniqueId]);

  const sections = data ? [
    { key: 'explanation', icon: '📖', title: 'Explication', content: data.explanation, color: '#00eeff' },
    { key: 'impact', icon: '💥', title: 'Impact Opérationnel', content: data.impact, color: '#ef4444' },
    { key: 'example', icon: '🔬', title: 'Exemple Concret', content: data.example, color: '#f59e0b' },
    { key: 'mitigation', icon: '🛡', title: 'Remédiation', content: data.mitigation, color: '#22c55e' },
  ] : [];

  return (
    <div 
      className="mt-2 rounded-lg border overflow-hidden transition-all"
      style={{ 
        background: '#060a12',
        borderColor: `${tacticColor}44`,
        animation: 'pedagogySlideIn 0.3s ease-out',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b" style={{ borderColor: `${tacticColor}22`, background: `${tacticColor}08` }}>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-bold px-2 py-0.5 rounded" style={{ background: `${tacticColor}20`, color: tacticColor }}>{techniqueId}</span>
          <span className="text-sm font-bold text-white">{data?.name || techniqueId}</span>
        </div>
        <button 
          onClick={onClose}
          className="text-gray-500 hover:text-white text-xs px-2 py-1 rounded hover:bg-white/10 transition-colors font-mono"
        >
          ✕ Fermer
        </button>
      </div>

      {/* Body */}
      <div className="p-3">
        {loading ? (
          <div className="flex flex-col gap-3 animate-pulse">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="flex items-start gap-3 p-3 rounded bg-white/[0.02]">
                <div className="w-6 h-6 rounded bg-gray-800 flex-shrink-0" />
                <div className="flex-1 space-y-2">
                  <div className="h-3 bg-gray-800 rounded w-32" />
                  <div className="h-2 bg-gray-800/50 rounded w-full" />
                  <div className="h-2 bg-gray-800/50 rounded w-3/4" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {sections.map(sec => (
              <div 
                key={sec.key}
                className="p-3 rounded-lg border-l-[3px] transition-all hover:bg-white/[0.02]"
                style={{ borderLeftColor: sec.color, background: `${sec.color}05` }}
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-sm">{sec.icon}</span>
                  <span className="text-[11px] font-bold uppercase tracking-wider" style={{ color: sec.color }}>{sec.title}</span>
                </div>
                <p className="text-xs text-gray-300 leading-relaxed font-mono" style={{ lineHeight: '1.7' }}>
                  {sec.content}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      <style>{`
        @keyframes pedagogySlideIn {
          from { opacity: 0; max-height: 0; transform: translateY(-8px); }
          to { opacity: 1; max-height: 600px; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
});
TechniquePedagogyPanel.displayName = 'TechniquePedagogyPanel';

const TTPDetailView = React.memo(({ techniques }: { techniques: any[] }) => {
  const [expandedTechniqueId, setExpandedTechniqueId] = useState<string | null>(null);

  if (!techniques || techniques.length === 0) {
    return <div className="onyx-card flex items-center justify-center text-gray-500 font-mono text-xs py-8">No MITRE TTPs mapped for this actor</div>;
  }

  const grouped: Record<string, { id: string; name: string }[]> = {};
  for (const t of techniques) {
    const isObj = typeof t === 'object' && t !== null;
    const tid = isObj ? t.id : t;
    const meta = isObj 
        ? { name: t.name || tid, tactic: (t.tactics && t.tactics.length > 0 ? t.tactics[0] : 'Uncategorized') }
        : (TECHNIQUE_METADATA[tid] || { name: tid, tactic: 'Uncategorized' });
        
    if (!grouped[meta.tactic]) grouped[meta.tactic] = [];
    grouped[meta.tactic].push({ id: tid, name: meta.name });
  }

  const tacticColors: Record<string, string> = {
    'Reconnaissance': '#6366f1', 'Initial Access': '#ef4444', 'Execution': '#f97316',
    'Persistence': '#a855f7', 'Privilege Escalation': '#ec4899', 'Defense Evasion': '#8b5cf6',
    'Credential Access': '#f59e0b', 'Discovery': '#22c55e', 'Lateral Movement': '#14b8a6',
    'Collection': '#3b82f6', 'Command and Control': '#ff3b5c', 'Exfiltration': '#ef4444',
    'Impact': '#dc2626', 'Uncategorized': '#6b7280',
  };

  const handleTechniqueClick = (tid: string) => {
    setExpandedTechniqueId(prev => prev === tid ? null : tid);
  };

  return (
    <div className="flex flex-col gap-2">
      <h3 className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider flex items-center gap-2">
        <span style={{ color: '#f59e0b' }}>⚔</span> MITRE ATT&CK TTPs
        <span className="text-[10px] font-normal text-gray-600">({techniques.length} techniques)</span>
      </h3>
      <div className="text-[9px] text-gray-600 font-mono mb-3">Cliquez sur une technique pour afficher l'analyse détaillée</div>
      <div className="flex flex-col gap-3">
        {Object.entries(grouped).map(([tactic, techs]) => (
          <div key={tactic}>
            <div className="flex items-center gap-2 mb-1.5">
              <div className="w-1.5 h-1.5 rounded-full" style={{ background: tacticColors[tactic] || '#6b7280' }} />
              <span className="text-[10px] uppercase font-bold tracking-wider" style={{ color: tacticColors[tactic] || '#6b7280' }}>{tactic}</span>
              <div className="flex-1 h-px bg-gray-800" />
            </div>
            <div className="flex flex-col gap-1 ml-3">
              <div className="flex flex-wrap gap-1.5">
                {techs.map(t => (
                  <div 
                    key={t.id} 
                    className="cursor-pointer"
                    onClick={() => handleTechniqueClick(t.id)}
                  >
                    <div 
                      className="text-[10px] font-mono px-2 py-1 rounded border transition-all hover:brightness-125"
                      style={{ 
                        background: expandedTechniqueId === t.id 
                          ? `${tacticColors[tactic] || '#6b7280'}22` 
                          : `${tacticColors[tactic] || '#6b7280'}11`,
                        borderColor: expandedTechniqueId === t.id 
                          ? tacticColors[tactic] || '#6b7280'
                          : `${tacticColors[tactic] || '#6b7280'}33`,
                        color: '#e5e7eb',
                        boxShadow: expandedTechniqueId === t.id 
                          ? `0 0 12px ${tacticColors[tactic] || '#6b7280'}33` 
                          : 'none',
                      }}
                    >
                      <span style={{ color: tacticColors[tactic] || '#6b7280', fontWeight: 'bold' }}>{t.name}</span>
                      <span className="ml-1.5 text-gray-600">{expandedTechniqueId === t.id ? '▾' : '▸'}</span>
                    </div>
                  </div>
                ))}
              </div>
              {/* Render pedagogy panel inline below the tactic group if a technique from this group is expanded */}
              {techs.some(t => t.id === expandedTechniqueId) && expandedTechniqueId && (
                <TechniquePedagogyPanel 
                  techniqueId={expandedTechniqueId} 
                  tacticColor={tacticColors[tactic] || '#6b7280'}
                  onClose={() => setExpandedTechniqueId(null)}
                />
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
});
TTPDetailView.displayName = 'TTPDetailView';


// ─── SUB 4: LINK GRAPH (D3 + Web Worker + Canvas + Quadtree + Tooltips + Legend) ─

const LinkGraph = React.memo(({ data, selectedNodeId, onNodeClick }: { data: { nodes: GraphNode[], links: GraphLink[] }; selectedNodeId: string | null; onNodeClick: (id: string) => void }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const workerRef = useRef<Worker | null>(null);
  
  const nodesRef = useRef<GraphNode[]>([]);
  const linksRef = useRef<GraphLink[]>([]);
  const transformRef = useRef<d3.ZoomTransform>(d3.zoomIdentity);
  const hoveredNodeRef = useRef<GraphNode | null>(null);
  const quadtreeRef = useRef<d3.Quadtree<GraphNode> | null>(null);
  const rafRef = useRef<number | null>(null);

  // Tooltip state (React-managed for overlay rendering)
  const [tooltip, setTooltip] = useState<{ x: number; y: number; node: GraphNode } | null>(null);

  const drawCanvas = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d', { alpha: false });
    if (!ctx) return;
    
    const w = canvas.width;
    const h = canvas.height;
    const t = transformRef.current;
    
    ctx.fillStyle = '#050a0f';
    ctx.fillRect(0, 0, w, h);
    
    ctx.save();
    ctx.translate(t.x, t.y);
    ctx.scale(t.k, t.k);
    
    const nodes = nodesRef.current;
    const links = linksRef.current;
    const hoveredNode = hoveredNodeRef.current;
    const hoveredId = hoveredNode?.id || null;

    // Fast determine neighbor set if hovered
    const neighborSet = new Set<string>();
    if (hoveredId) {
      neighborSet.add(hoveredId);
      for (const l of links) {
        const sid = typeof l.source === 'string' ? l.source : (l.source as any).id;
        const tid = typeof l.target === 'string' ? l.target : (l.target as any).id;
        if (sid === hoveredId) neighborSet.add(tid);
        if (tid === hoveredId) neighborSet.add(sid);
      }
    }

    // ── Draw Links ──
    for (const l of links) {
      const src = (typeof l.source === 'string' ? nodes.find(n => n.id === l.source) : l.source) as GraphNode;
      const tgt = (typeof l.target === 'string' ? nodes.find(n => n.id === l.target) : l.target) as GraphNode;
      if (!src || !tgt || src.x == null || src.y == null || tgt.x == null || tgt.y == null) continue;

      const isHighlighted = hoveredId ? (neighborSet.has(src.id) && neighborSet.has(tgt.id)) : false;
      
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      
      if (isHighlighted) {
        ctx.strokeStyle = '#00eeff';
        ctx.lineWidth = 2;
        ctx.globalAlpha = 0.9;
      } else {
        ctx.strokeStyle = hoveredId ? 'rgba(255,255,255,0.03)' : 'rgba(255,255,255,0.1)';
        ctx.lineWidth = 0.5;
        ctx.globalAlpha = 1;
      }
      ctx.stroke();
    }
    ctx.globalAlpha = 1;

    // ── Draw Nodes ──
    for (const n of nodes) {
      if (n.x == null || n.y == null) continue;
      
      const isHovered = hoveredId === n.id;
      const isNeighbor = hoveredId ? neighborSet.has(n.id) : true;
      const isSelected = selectedNodeId === n.id;
      
      const r = n.type === 'actor' ? 18 : n.type === 'tool' ? 12 : n.type === 'ttp' ? 9 : 5;
      n.radius = r;
      const color = isSelected ? '#ffffff' : (typeColors[n.type] || typeColors.default);
      
      ctx.globalAlpha = isNeighbor ? 1.0 : 0.08;
      
      // Glow for hovered node
      if (isHovered) {
        ctx.shadowColor = color;
        ctx.shadowBlur = 18;
      }
      
      // Draw node circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
      
      // Outer ring for actor nodes
      if (n.type === 'actor') {
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 4, 0, 2 * Math.PI);
        ctx.stroke();
      }
      
      ctx.shadowBlur = 0;
      
      // ── Draw Node Labels ──
      // Show labels when: zoomed in enough OR node is hovered/neighbor of hovered
      const showLabel = t.k > 0.6 || isHovered || (hoveredId && isNeighbor);
      if (showLabel && isNeighbor) {
        ctx.font = `${isHovered ? 'bold ' : ''}${n.type === 'actor' ? 12 : 10}px "JetBrains Mono", monospace`;
        ctx.fillStyle = isHovered ? '#ffffff' : '#9ca3af';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        const label = n.name.length > 20 ? n.name.slice(0, 18) + '…' : n.name;
        ctx.fillText(label, n.x, n.y + r + 5);
      }
      
      ctx.globalAlpha = 1.0;
    }
    
    ctx.restore();
  }, [selectedNodeId]);

  // Handle Resize
  useEffect(() => {
    if (!containerRef.current || !canvasRef.current) return;
    const observer = new ResizeObserver(entries => {
      for (let entry of entries) {
        const { width, height } = entry.contentRect;
        if (canvasRef.current) {
          canvasRef.current.width = width;
          canvasRef.current.height = height;
          drawCanvas();
        }
      }
    });
    observer.observe(containerRef.current);
    const rect = containerRef.current.getBoundingClientRect();
    canvasRef.current.width = rect.width;
    canvasRef.current.height = rect.height;
    return () => observer.disconnect();
  }, [drawCanvas]);

  // Init Web Worker & Data
  useEffect(() => {
    if (!data.nodes.length) return;
    nodesRef.current = data.nodes.map(n => ({ ...n }));
    linksRef.current = data.links.map(l => ({ ...l }));
    
    const worker = new Worker(new URL('../workers/d3.worker.ts', import.meta.url));
    workerRef.current = worker;
    
    worker.postMessage({
      type: 'INIT',
      nodes: data.nodes,
      links: data.links,
      width: canvasRef.current?.width || 800,
      height: canvasRef.current?.height || 600
    });

    worker.onmessage = (e) => {
      if (e.data.type === 'TICK') {
        const coords = new Float32Array(e.data.coords);
        for (let i = 0; i < nodesRef.current.length; i++) {
          nodesRef.current[i].x = coords[i * 2];
          nodesRef.current[i].y = coords[i * 2 + 1];
        }
        quadtreeRef.current = d3.quadtree<GraphNode>()
          .x(d => d.x!)
          .y(d => d.y!)
          .addAll(nodesRef.current);

        if (rafRef.current) cancelAnimationFrame(rafRef.current);
        rafRef.current = requestAnimationFrame(drawCanvas);
      }
    };

    return () => {
       worker.terminate();
       if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [data, drawCanvas]);

  // Interactive Zoom & Hit Detection with Tooltip
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const zoom = d3.zoom<HTMLCanvasElement, unknown>()
      .scaleExtent([0.1, 8])
      .on('zoom', (e) => {
        transformRef.current = e.transform;
        if (rafRef.current) cancelAnimationFrame(rafRef.current);
        rafRef.current = requestAnimationFrame(drawCanvas);
      });

    d3.select(canvas).call(zoom);
    
    const handleMouseMove = (e: MouseEvent) => {
      if (!quadtreeRef.current) return;
      const rect = canvas.getBoundingClientRect();
      const t = transformRef.current;
      const x = (e.clientX - rect.left - t.x) / t.k;
      const y = (e.clientY - rect.top - t.y) / t.k;
      const closest = quadtreeRef.current.find(x, y, 20);
      
      if (closest) {
        if (hoveredNodeRef.current?.id !== closest.id) {
           hoveredNodeRef.current = closest;
           canvas.style.cursor = 'pointer';
           // Position tooltip relative to container
           const screenX = closest.x! * t.k + t.x;
           const screenY = closest.y! * t.k + t.y;
           setTooltip({ x: screenX, y: screenY, node: closest });
           drawCanvas();
        }
      } else {
        if (hoveredNodeRef.current !== null) {
           hoveredNodeRef.current = null;
           canvas.style.cursor = 'grab';
           setTooltip(null);
           drawCanvas();
        }
      }
    };

    const handleClick = () => {
      if (hoveredNodeRef.current) {
         onNodeClick(hoveredNodeRef.current.id);
      }
    };

    const handleLeave = () => {
      hoveredNodeRef.current = null;
      setTooltip(null);
      drawCanvas();
    };

    canvas.addEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('click', handleClick);
    canvas.addEventListener('mouseleave', handleLeave);

    return () => {
      d3.select(canvas).on('.zoom', null);
      canvas.removeEventListener('mousemove', handleMouseMove);
      canvas.removeEventListener('click', handleClick);
      canvas.removeEventListener('mouseleave', handleLeave);
    };
  }, [drawCanvas, onNodeClick]);

  return (
    <div ref={containerRef} className="onyx-card relative flex-1 p-0 overflow-hidden" style={{ minHeight: 400 }}>
       <canvas ref={canvasRef} className="absolute inset-0 cursor-grab active:cursor-grabbing w-full h-full" />
       
       {/* ── Visual Legend ── */}
       <div className="absolute top-3 left-3 z-10 flex flex-col gap-1 bg-black/80 backdrop-blur-sm px-3 py-2 rounded-lg border border-gray-800/60">
         <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mb-1">Node Types</div>
         {Object.entries(typeColors).filter(([k]) => k !== 'default').map(([type, color]) => (
           <div key={type} className="flex items-center gap-2">
             <span className="text-sm" style={{ lineHeight: 1 }}>{typeIcons[type]}</span>
             <div className="w-2 h-2 rounded-full" style={{ background: color }} />
             <span className="text-[10px] font-mono text-gray-400">{typeLabels[type]}</span>
           </div>
         ))}
         <div className="text-[8px] text-gray-600 font-mono mt-1 border-t border-gray-800 pt-1">{(data.nodes || []).length} Nodes · D3 Worker</div>
       </div>

       {/* ── Hover Tooltip ── */}
       {tooltip && (
         <div 
           className="absolute z-20 pointer-events-none"
           style={{ 
             left: tooltip.x, 
             top: tooltip.y,
             transform: 'translate(-50%, -120%)',
           }}
         >
           <div className="bg-black/95 border rounded-lg px-3 py-2 shadow-xl" style={{ borderColor: typeColors[tooltip.node.type] || '#6b7280' }}>
             <div className="flex items-center gap-2 mb-1">
               <span className="text-sm">{typeIcons[tooltip.node.type]}</span>
               <span className="text-xs font-bold text-white">{tooltip.node.name}</span>
             </div>
             <div className="text-[9px] font-mono uppercase tracking-wider" style={{ color: typeColors[tooltip.node.type] }}>{typeLabels[tooltip.node.type]}</div>
             <div className="text-[8px] text-gray-500 font-mono mt-1">ID: {tooltip.node.id.slice(0, 30)}…</div>
           </div>
         </div>
       )}
    </div>
  );
});
LinkGraph.displayName = 'LinkGraph';


// ─── SUB 5: MITRE HEATMAP (CSS Grid — 14 Tactic Columns) ───────────────────

const _ALL_TACTICS = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery',
  'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact',
];

const _TACTIC_ABBREVIATIONS: Record<string, string> = {
  'Reconnaissance': 'RECON', 'Initial Access': 'INIT', 'Execution': 'EXEC',
  'Persistence': 'PERS', 'Privilege Escalation': 'PRIV', 'Defense Evasion': 'DEF',
  'Credential Access': 'CRED', 'Discovery': 'DISC', 'Lateral Movement': 'LAT',
  'Collection': 'COLL', 'Command and Control': 'C2', 'Exfiltration': 'EXFIL', 'Impact': 'IMP',
};

const MitreHeatmap = React.memo(({ heatmapData }: { heatmapData?: HeatmapData[] }) => {
  if (!heatmapData || !heatmapData.length) return <div className="onyx-card flex-1 flex items-center justify-center text-gray-500 font-mono text-xs">No MITRE Activity Detected</div>;
  
  // Group by tactic
  const grouped = heatmapData.reduce((acc, curr) => {
    if (!acc[curr.tactic]) acc[curr.tactic] = [];
    acc[curr.tactic].push(curr);
    return acc;
  }, {} as Record<string, HeatmapData[]>);

  const getIntensityColor = (intensity: number) => {
    if (intensity > 80) return { bg: '#ef444450', border: '#ef4444', text: '#fca5a5' };
    if (intensity > 50) return { bg: '#f9731640', border: '#f97316', text: '#fdba74' };
    if (intensity > 20) return { bg: '#eab30830', border: '#eab308', text: '#fde047' };
    return { bg: '#22c55e20', border: '#22c55e', text: '#86efac' };
  };

  // Find max column height for uniform grid
  const maxTechniques = Math.max(...Object.values(grouped).map(t => t.length), 1);

  return (
    <div className="onyx-card flex-1 flex flex-col gap-3">
      {/* Title + Gradient Legend */}
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-bold uppercase text-gray-400 tracking-wider flex items-center gap-2">
          <span style={{ color: '#f59e0b' }}>⬡</span> MITRE ATT&CK Tactic/Technique Grid
        </h3>
        <div className="flex items-center gap-3 text-[9px] font-mono text-gray-500">
          <span>Low</span>
          <div className="flex h-3 rounded overflow-hidden border border-gray-700">
            <div className="w-6" style={{ background: '#22c55e30' }} />
            <div className="w-6" style={{ background: '#eab30850' }} />
            <div className="w-6" style={{ background: '#f9731660' }} />
            <div className="w-6" style={{ background: '#ef444470' }} />
          </div>
          <span>Critical</span>
        </div>
      </div>

      {/* CSS Grid — 13 tactic columns */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: `repeat(${_ALL_TACTICS.length}, minmax(90px, 1fr))`,
        gap: '3px',
        overflowX: 'auto',
        paddingBottom: 8,
      }}>
        {/* Header row — tactic labels */}
        {_ALL_TACTICS.map(tactic => {
          const hasData = !!grouped[tactic];
          return (
            <div key={`hdr-${tactic}`} style={{
              padding: '6px 4px',
              textAlign: 'center',
              fontSize: '9px',
              fontWeight: 800,
              letterSpacing: '0.1em',
              textTransform: 'uppercase' as const,
              color: hasData ? '#00eeff' : '#374151',
              borderBottom: hasData ? '2px solid #00eeff44' : '2px solid #1f293700',
              fontFamily: 'var(--font-mono, monospace)',
            }}>
              {_TACTIC_ABBREVIATIONS[tactic] || tactic.slice(0, 5)}
            </div>
          );
        })}

        {/* Technique cells — one row per technique slot */}
        {Array.from({ length: maxTechniques }).map((_, rowIdx) => (
          <React.Fragment key={`row-${rowIdx}`}>
            {_ALL_TACTICS.map(tactic => {
              const techniques = grouped[tactic] || [];
              const t = techniques[rowIdx];
              if (!t) return <div key={`empty-${tactic}-${rowIdx}`} style={{ minHeight: 32 }} />;
              const ic = getIntensityColor(t.intensity);
              return (
                <div
                  key={`${tactic}-${t.technique}`}
                  className="group relative"
                  style={{
                    background: ic.bg,
                    borderRadius: 4,
                    padding: '4px 6px',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    borderLeft: `2px solid ${ic.border}`,
                    minHeight: 32,
                  }}
                >
                  <div style={{ fontSize: '9px', fontFamily: 'monospace', color: ic.text, fontWeight: 700, lineHeight: '1.3' }}>
                    {t.technique.split(':')[0]}
                  </div>
                  <div style={{ fontSize: '8px', fontFamily: 'monospace', color: '#6b7280', lineHeight: '1.2', marginTop: 1 }}>
                    {t.intensity}%
                  </div>
                  {/* Hover tooltip */}
                  <div className="absolute bottom-full left-0 mb-1 opacity-0 group-hover:opacity-100 transition-opacity z-20 pointer-events-none" style={{ minWidth: 180 }}>
                    <div style={{ background: '#000000ee', border: '1px solid #374151', borderRadius: 6, padding: '6px 8px', fontSize: '9px', fontFamily: 'monospace', color: '#d1d5db' }}>
                      <div style={{ color: '#00eeff', fontWeight: 700, marginBottom: 2 }}>{t.technique}</div>
                      <div>Tactic: {tactic}</div>
                      <div>Intensity: {t.intensity}%</div>
                      <div>Last seen: {new Date(t.last_seen).toLocaleDateString()}</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
});
MitreHeatmap.displayName = 'MitreHeatmap';


// ─── SUB 5b: ACTIVITY CALENDAR (GitHub Contribution-style) ──────────────────

const ActivityCalendar = React.memo(({ heatmapData }: { heatmapData?: HeatmapData[] }) => {
  // Generate a 26-week × 7-day grid with deterministic intensity derived from techniques
  const weeks = 26;
  const days = 7;
  const dayLabels = ['S', 'M', 'T', 'W', 'T', 'F', 'S'];

  // Build intensity map from technique data
  const totalIntensity = heatmapData?.reduce((s, h) => s + h.intensity, 0) || 0;
  const techniqueCount = heatmapData?.length || 0;

  const cells = useMemo(() => {
    const result: number[][] = [];
    for (let w = 0; w < weeks; w++) {
      const row: number[] = [];
      for (let d = 0; d < days; d++) {
        // Deterministic: hash-based from week + day + technique count
        const seed = (w * 7 + d + techniqueCount * 13) % 100;
        const hasActivity = seed < (techniqueCount * 8); // More techniques = more active days
        if (!hasActivity) {
          row.push(0);
        } else {
          // Intensity bucket: 1-4 based on seed distribution
          const bucket = 1 + Math.floor((seed % 40) / 10);
          row.push(Math.min(bucket, 4));
        }
      }
      result.push(row);
    }
    return result;
  }, [techniqueCount]);

  const intensityColors = ['#161b22', '#0e4429', '#006d32', '#26a641', '#39d353'];
  const activeDays = cells.flat().filter(c => c > 0).length;

  return (
    <div className="onyx-card flex-1 flex flex-col gap-3" style={{ marginTop: 4 }}>
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-bold uppercase text-gray-400 tracking-wider flex items-center gap-2">
          <span style={{ color: '#26a641' }}>◈</span> Technique Activity Calendar
          <span className="text-[10px] font-normal text-gray-600">({activeDays} active days · {techniqueCount} techniques)</span>
        </h3>
        <div className="flex items-center gap-2 text-[9px] font-mono text-gray-500">
          <span>Less</span>
          {intensityColors.map((c, i) => (
            <div key={i} style={{ width: 10, height: 10, borderRadius: 2, background: c }} />
          ))}
          <span>More</span>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 2, overflowX: 'auto', paddingBottom: 4 }}>
        {/* Day labels */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginRight: 4, paddingTop: 0 }}>
          {dayLabels.map((label, i) => (
            <div key={i} style={{ width: 14, height: 12, fontSize: '8px', fontFamily: 'monospace', color: '#484f58', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{i % 2 === 1 ? label : ''}</div>
          ))}
        </div>
        {/* Weeks grid */}
        {cells.map((week, wi) => (
          <div key={wi} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {week.map((intensity, di) => (
              <div
                key={`${wi}-${di}`}
                style={{
                  width: 12,
                  height: 12,
                  borderRadius: 2,
                  background: intensityColors[intensity],
                  transition: 'all 0.15s',
                  cursor: intensity > 0 ? 'pointer' : 'default',
                }}
                title={intensity > 0 ? `Week ${wi + 1}, ${dayLabels[di]}: ${intensity} observation(s)` : ''}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
});
ActivityCalendar.displayName = 'ActivityCalendar';


// ─── SUB 6: ATTACK CHRONOLOGY (Alternating Vertical Timeline with CSS Badges) ─

const AttackTimeline = React.memo(({ events }: { events?: TimelineEvent[] }) => {
  if (!events || !events.length) return <div className="onyx-card flex items-center justify-center text-gray-500 font-mono text-xs py-8">No chronological events recorded</div>;

  const phaseColors: Record<string, string> = {
    'Reconnaissance': '#6366f1',
    'Initial Access': '#ef4444',
    'Execution': '#f97316',
    'Persistence': '#14b8a6',
    'Privilege Escalation': '#ec4899',
    'Defense Evasion': '#8b5cf6',
    'Credential Access': '#eab308',
    'Discovery': '#06b6d4',
    'Lateral Movement': '#14b8a6',
    'Collection': '#f59e0b',
    'Command and Control': '#ff3b5c',
    'Exfiltration': '#dc2626',
    'Impact': '#dc2626',
    // Legacy keys from old data
    'Initial Compromise': '#ef4444',
    'Establish Foothold': '#f97316',
    'Data Exfiltration': '#f59e0b',
    'C2 Established': '#ff3b5c',
  };

  return (
    <div className="onyx-card overflow-y-auto" style={{ maxHeight: 500 }}>
      <h3 className="text-xs font-bold uppercase text-gray-400 mb-5 tracking-wider flex items-center gap-2">
        <span style={{ color: '#00eeff' }}>◎</span> Attack Kill Chain Chronology
        <span className="text-[10px] font-normal text-gray-600">({events.length} events)</span>
      </h3>
      
      {/* Alternating vertical timeline */}
      <div className="relative">
        {/* Center spine */}
        <div className="absolute left-1/2 top-0 bottom-0 w-px bg-gradient-to-b from-[#00eeff33] via-[#ef444433] to-transparent" style={{ transform: 'translateX(-50%)' }} />
        
        {events.map((ev, i) => {
          const isLeft = i % 2 === 0;
          const phaseColor = phaseColors[ev.phase] || sevColor(ev.severity);
          
          return (
            <div key={ev.id} className="relative flex items-start mb-6" style={{ minHeight: 60 }}>
              {/* Left side content */}
              <div className={`w-[calc(50%-20px)] ${isLeft ? 'pr-4 text-right' : 'order-3 pl-4 text-left'}`}>
                {isLeft ? (
                  <TimelineCard event={ev} phaseColor={phaseColor} align="right" />
                ) : (
                  <div className="text-[10px] text-gray-600 font-mono pt-1">
                    {new Date(ev.date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}
                  </div>
                )}
              </div>
              
              {/* Center node */}
              <div className="flex-shrink-0 w-10 flex justify-center order-2 relative z-10">
                <div className="w-6 h-6 rounded-full border-2 flex items-center justify-center" 
                  style={{ borderColor: phaseColor, background: '#0a0f1a' }}
                >
                  <span style={{ fontSize: '10px' }}>{ev.icon || '◈'}</span>
                </div>
              </div>

              {/* Right side content */}
              <div className={`w-[calc(50%-20px)] ${isLeft ? 'order-3 pl-4 text-left' : 'pr-4 text-right order-1'}`}>
                {isLeft ? (
                  <div className="text-[10px] text-gray-600 font-mono pt-1">
                    {new Date(ev.date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}
                  </div>
                ) : (
                  <TimelineCard event={ev} phaseColor={phaseColor} align="left" />
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
});
AttackTimeline.displayName = 'AttackTimeline';

// Timeline card sub-component for clean alternating layout
function TimelineCard({ event, phaseColor, align }: { event: TimelineEvent; phaseColor: string; align: 'left' | 'right' }) {
  return (
    <div 
      className="p-3 rounded-lg border transition-all hover:brightness-110" 
      style={{ 
        background: '#0a0f1a',
        borderColor: `${phaseColor}33`,
        borderLeft: align === 'left' ? `3px solid ${phaseColor}` : undefined,
        borderRight: align === 'right' ? `3px solid ${phaseColor}` : undefined,
      }}
    >
      {/* Phase Badge */}
      <div className="flex items-center gap-2 mb-1.5" style={{ justifyContent: align === 'right' ? 'flex-end' : 'flex-start' }}>
        <span 
          className="text-[9px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full"
          style={{ background: `${phaseColor}20`, color: phaseColor, border: `1px solid ${phaseColor}44` }}
        >
          {event.phase}
        </span>
        <span 
          className="text-[8px] uppercase font-bold px-1.5 py-0.5 rounded"
          style={{ background: `${sevColor(event.severity)}20`, color: sevColor(event.severity) }}
        >
          {event.severity}
        </span>
      </div>
      <div className="text-[11px] text-gray-300 leading-relaxed font-mono">{event.description}</div>
    </div>
  );
}


// ─── SUB 7: ACTOR SUMMARY STATS BAR ─────────────────────────────────────────

const ActorStatsBar = React.memo(({ actor }: { actor: ThreatActor }) => {
  const stats = [
    { label: 'TTPs', value: actor.techniques?.length || 0, color: '#f59e0b' },
    { label: 'Tools', value: actor.tools?.length || 0, color: '#00eeff' },
    { label: 'Aliases', value: actor.aliases?.length || 0, color: '#a855f7' },
    { label: 'Live IOCs', value: actor.live_iocs || 0, color: '#ef4444' },
  ];

  return (
    <div className="grid grid-cols-4 gap-2">
      {stats.map(s => (
        <div key={s.label} className="onyx-card text-center p-3" style={{ borderBottom: `2px solid ${s.color}` }}>
          <div className="text-2xl font-bold font-mono" style={{ color: s.color }}>{s.value}</div>
          <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold mt-1">{s.label}</div>
        </div>
      ))}
    </div>
  );
});
ActorStatsBar.displayName = 'ActorStatsBar';


// ─── MAIN COMPONENT ─────────────────────────────────────────────────────────

export default function ThreatActorIntel() {
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [loading, setLoading] = useState(true);
  const selectedActorId = useOnyxStore(s => s.selectedActorId);
  const setSelectedActorId = useOnyxStore(s => s.setSelectedActorId);
  const [activeGraphNode, setActiveGraphNode] = useState<string | null>(null);
  
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    profile: true,
    stats: true,
    ttps: true,
    arsenal: true,
    graph: true,
    heatmap: true,
    timeline: true,
  });

  const toggleSection = (key: string) => {
    setOpenSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch(`${API}/api/v1/dashboard/mitre-threat-actors`);
        if (res.ok) {
           const data = await res.json();
           setActors(data.threat_actors);
           if (data.threat_actors.length > 0 && !selectedActorId) {
             setSelectedActorId(data.threat_actors[0].id);
           }
        }
      } catch (err) {}
      setLoading(false);
    }
    load();
    const int = setInterval(load, 30000);
    return () => clearInterval(int);
  }, [selectedActorId, setSelectedActorId]);

  if (loading) return <div className="text-gray-500 text-center p-10 font-mono">Loading Enterprise Analytics...</div>;

  const currentActor = actors.find(a => a.id === selectedActorId) || actors[0];

  return (
    <div className="flex flex-col gap-4 h-full min-h-[800px]">
       <div className="flex gap-4">
         {/* LEFT LIST */}
         <div className="w-[280px] flex flex-col gap-3 overflow-y-auto pr-2" style={{ maxHeight: 900 }}>
            {actors.map(a => (
              <div key={a.id} onClick={() => setSelectedActorId(a.id)} className={`p-3 rounded-lg cursor-pointer transition-all border ${selectedActorId === a.id ? 'bg-[#00eeff]/5 border-[#00eeff]' : 'bg-[#0a0f1a] border-transparent hover:border-gray-700'}`}>
                <div className="flex justify-between items-center mb-1">
                  <span className={`font-bold text-sm ${selectedActorId === a.id ? 'text-[#00eeff]' : 'text-gray-200'}`}>{a.name}</span>
                  {a.status === 'Active Now' && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
                </div>
                <div className="text-[10px] text-gray-500 font-mono truncate">{a.description}</div>
                <div className="flex gap-1 mt-1.5">
                  <span className="text-[8px] px-1.5 py-0.5 rounded bg-white/5 text-gray-500 font-mono">{a.techniques?.length || 0} TTPs</span>
                  <span className="text-[8px] px-1.5 py-0.5 rounded bg-white/5 text-gray-500 font-mono">{a.tools?.length || 0} Tools</span>
                  <span className="text-[8px] px-1.5 py-0.5 rounded font-mono" style={{ 
                    background: `${sevColor(a.severity)}15`,
                    color: sevColor(a.severity)
                  }}>{a.severity}</span>
                </div>
              </div>
            ))}
         </div>

         {/* RIGHT MAIN PANEL: DIAMOND MODEL DOSSIER */}
         <div className="flex-1 flex flex-col gap-4 overflow-y-auto" style={{ maxHeight: 900 }}>
            
            {/* DOSSIER HEADER */}
            <div className="flex bg-[#050a0f] border border-gray-800 rounded-lg p-4 items-center justify-between">
              <div>
                <h1 className="text-xl font-bold font-mono text-white tracking-widest uppercase">Intrusion Analysis Dossier</h1>
                <p className="text-[10px] text-gray-500 font-mono tracking-widest mt-1">Diamond Model Framework — Onyx Intelligence</p>
              </div>
              <div className="flex items-center gap-6">
                <div className="text-right">
                   <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold">Tracked IOCs</div>
                   <div className="text-lg font-bold text-red-500 font-mono">{currentActor?.live_iocs || 0}</div>
                </div>
                <div className="text-right">
                   <div className="text-[9px] uppercase tracking-wider text-gray-500 font-bold">Tool Complexity</div>
                   <div className="text-lg font-bold text-blue-500 font-mono">{currentActor?.tools?.length || 0}</div>
                </div>
              </div>
            </div>

            {/* DIAMOND MODEL GRID */}
            <div className="grid grid-cols-2 gap-4">
               {/* QUADRANT I: ADVERSARY */}
               <div className="onyx-card flex flex-col gap-4" style={{ borderTop: `4px solid ${sevColor(currentActor?.severity || 'low')}`}}>
                 <h3 className="text-xs font-bold uppercase text-gray-300 tracking-wider flex items-center gap-2 border-b border-gray-800 pb-2">
                   <span style={{ color: sevColor(currentActor?.severity || 'low') }}>☠</span> QUADRANT I: ADVERSARY
                 </h3>
                 <ProfileView actor={currentActor} />
               </div>

               {/* QUADRANT II: VICTIM */}
               <div className="onyx-card flex flex-col gap-4" style={{ borderTop: '4px solid #3b82f6'}}>
                 <h3 className="text-xs font-bold uppercase text-gray-300 tracking-wider flex items-center gap-2 border-b border-gray-800 pb-2">
                   <span className="text-blue-500">🎯</span> QUADRANT II: VICTIM
                 </h3>
                 <VictimView actor={currentActor} />
               </div>

               {/* QUADRANT III: CAPABILITY */}
               <div className="onyx-card flex flex-col gap-4" style={{ borderTop: '4px solid #a855f7'}}>
                 <h3 className="text-xs font-bold uppercase text-gray-300 tracking-wider flex items-center gap-2 border-b border-gray-800 pb-2">
                   <span className="text-purple-500">⚔</span> QUADRANT III: CAPABILITY
                 </h3>
                 <ArsenalView actor={currentActor} />
                 <div className="h-px bg-gray-800 my-2" />
                 <TTPDetailView techniques={currentActor?.techniques || []} />
               </div>

               {/* QUADRANT IV: INFRASTRUCTURE */}
               <div className="onyx-card flex flex-col gap-4" style={{ borderTop: '4px solid #00eeff'}}>
                 <h3 className="text-xs font-bold uppercase text-gray-300 tracking-wider flex items-center gap-2 border-b border-gray-800 pb-2">
                   <span className="text-cyan-400">📡</span> QUADRANT IV: INFRASTRUCTURE
                 </h3>
                 {currentActor?.graph_data && (
                   <LinkGraph 
                     data={currentActor.graph_data} 
                     selectedNodeId={activeGraphNode} 
                     onNodeClick={(id) => setActiveGraphNode(id)} 
                   />
                 )}
               </div>
            </div>

            {/* AUXILIARY VIEW */}
            <div className="onyx-card">
              <SectionHeader title="ATTACK KILL CHAIN CHRONOLOGY" icon="◎" isOpen={openSections.timeline} onToggle={() => toggleSection('timeline')} />
              {openSections.timeline && <AttackTimeline events={currentActor?.timeline_events} />}
            </div>
         </div>
       </div>
    </div>
  );
}


// ─── Accordion Section Header ───────────────────────────────────────────────

function SectionHeader({ title, icon, isOpen, onToggle, count }: { 
  title: string; icon: string; isOpen: boolean; onToggle: () => void; count?: number;
}) {
  return (
    <button
      onClick={onToggle}
      className="flex items-center gap-3 w-full text-left px-3 py-2 rounded-lg transition-colors hover:bg-white/5 group"
      style={{ 
        background: isOpen ? 'rgba(0,238,255,0.03)' : 'transparent',
        borderBottom: '1px solid rgba(255,255,255,0.05)'
      }}
    >
      <span className="text-sm" style={{ color: isOpen ? '#00eeff' : '#6b7280' }}>{icon}</span>
      <span className="text-[11px] uppercase tracking-[0.15em] font-bold" style={{ color: isOpen ? '#e5e7eb' : '#6b7280' }}>
        {title}
      </span>
      {count !== undefined && (
        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-gray-500">{count}</span>
      )}
      <span className="ml-auto text-gray-600 text-xs transition-transform" style={{ transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}>
        ▾
      </span>
    </button>
  );
}
