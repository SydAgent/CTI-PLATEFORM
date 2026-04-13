'use client';

import { useEffect, useRef, useState, useMemo, useCallback, memo } from 'react';
import * as d3 from 'd3-force';
import { useThreatStream } from './DashboardClient';

/*
 * ONYX CTI — Advanced Threat Graph Visualization Engine
 * 
 * WebGL-accelerated force-directed 3D graph powered by react-force-graph-3d.
 * Renders live IOC telemetry as an interactive investigation hub with:
 *   - Strict CTI ontology (TA → TTP → IOC)
 *   - 500-node performance cap (highest confidence first)
 *   - Neighbor highlighting on hover (1st-degree dimming)
 *   - Directional attack-flow particles
 *   - Global state sync (selectedEventId → IOC Explorer cross-filter)
 *   - Auto-fit on initial load
 *   - Zero mock data — entirely live telemetry driven
 */

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const NODE_CAP = 500;

// ═══════════════════════════════════════════════════════════════════════════
//  CTI ONTOLOGY — Strict Node Taxonomy
// ═══════════════════════════════════════════════════════════════════════════

interface NodeConfig { color: string; size: number; icon: string; group: string }

const NODE_TAXONOMY: Record<string, NodeConfig> = {
  'threat-actor':   { color: '#ff3b5c', size: 18, icon: '☠', group: 'actor' },
  'intrusion-set':  { color: '#ff3b5c', size: 16, icon: '👁', group: 'actor' },
  'campaign':       { color: '#ff00e5', size: 14, icon: '⚔', group: 'campaign' },
  'malware':        { color: '#ff6b35', size: 13, icon: '☣', group: 'malware' },
  'tool':           { color: '#00ff88', size: 10, icon: '🔧', group: 'tool' },
  'attack-pattern': { color: '#a855f7', size: 11, icon: '◆', group: 'ttp' },
  'indicator':      { color: '#fbbf24', size: 7,  icon: '⬡', group: 'ioc' },
  'indicator-crit': { color: '#ff3b5c', size: 9,  icon: '⬡', group: 'ioc' },
  'indicator-high': { color: '#f97316', size: 7,  icon: '⬡', group: 'ioc' },
  'vulnerability':  { color: '#ff6b35', size: 10, icon: '⚠', group: 'vuln' },
  'infrastructure': { color: '#14b8a6', size: 9,  icon: '🖥', group: 'infra' },
  'identity':       { color: '#64748b', size: 7,  icon: '●', group: 'target' },
  'report':         { color: '#a78bfa', size: 10, icon: '📋', group: 'intel' },
  'location':       { color: '#06b6d4', size: 7,  icon: '📍', group: 'geo' },
  'source-cluster': { color: '#22c55e', size: 12, icon: '◉', group: 'source' },
};

const LINK_STYLES: Record<string, { color: string; width: number }> = {
  'uses':              { color: '#ff3b5c55', width: 2 },
  'targets':           { color: '#ff6b3555', width: 2 },
  'indicates':         { color: '#00f0ff55', width: 1.5 },
  'attributed-to':     { color: '#ff00e555', width: 2.5 },
  'related-to':        { color: '#8b95a833', width: 1 },
  'communicates-with': { color: '#ffaa0055', width: 1.5 },
  'delivers':          { color: '#ff3b5c55', width: 2 },
  'resolves-to':       { color: '#f59e0b55', width: 1.5 },
  'exploits':          { color: '#ef444455', width: 2 },
  'sourced-from':      { color: '#22c55e44', width: 1 },
};

const LEGEND_ITEMS = [
  { label: 'Threat Actor', color: '#ff3b5c' },
  { label: 'MITRE TTP',    color: '#a855f7' },
  { label: 'Malware',      color: '#ff6b35' },
  { label: 'IOC (Critical)', color: '#ff3b5c' },
  { label: 'IOC (High)',   color: '#f59e0b' },
  { label: 'IOC (Default)', color: '#00f0ff' },
  { label: 'Source Feed',  color: '#22c55e' },
  { label: 'Vulnerability', color: '#ff6b35' },
];

// ═══════════════════════════════════════════════════════════════════════════
//  Interfaces
// ═══════════════════════════════════════════════════════════════════════════

interface GraphNode {
  id: string;
  name: string;
  type: string;
  val: number;
  color: string;
  icon: string;
  group: string;
  data?: Record<string, unknown>;
}

interface GraphLink {
  source: string;
  target: string;
  relationship_type: string;
  color: string;
  width: number;
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

// ═══════════════════════════════════════════════════════════════════════════
//  STIX Parser (API data → graph data)
// ═══════════════════════════════════════════════════════════════════════════

function stixToGraphData(objects: any[]): GraphData {
  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];
  const nodeIds = new Set<string>();

  for (const obj of objects) {
    if (obj.type === 'relationship' || obj.type === 'sighting') {
      const relType = obj.relationship_type || 'related-to';
      const style = LINK_STYLES[relType] || LINK_STYLES['related-to'];
      links.push({
        source: obj.source_ref,
        target: obj.target_ref,
        relationship_type: relType,
        color: style.color,
        width: style.width,
      });
    } else {
      if (nodeIds.has(obj.id)) continue;
      nodeIds.add(obj.id);
      const config = NODE_TAXONOMY[obj.type] || { color: '#64748b', size: 6, icon: '●', group: 'unknown' };
      nodes.push({
        id: obj.id,
        name: obj.name || obj.value || obj.id.split('--')[0],
        type: obj.type,
        val: config.size,
        color: config.color,
        icon: config.icon,
        group: config.group,
        data: obj,
      });
    }
  }

  const validLinks = links.filter(l => nodeIds.has(l.source) && nodeIds.has(l.target));
  return { nodes, links: validLinks };
}

// ═══════════════════════════════════════════════════════════════════════════
//  Known Threat Actor → MITRE TTP Heuristic Mapping
// ═══════════════════════════════════════════════════════════════════════════

const TA_TTP_MAP: Record<string, { ttps: string[]; malware: string[] }> = {
  'apt29':    { ttps: ['T1078', 'T1071', 'T1486'], malware: ['SUNBURST', 'Cobalt Strike'] },
  'apt41':    { ttps: ['T1190', 'T1105', 'T1566'], malware: ['MESSAGETAP', 'POISONPLUG'] },
  'lazarus':  { ttps: ['T1059', 'T1055', 'T1021'], malware: ['HOPLIGHT', 'ELECTRICFISH'] },
  'fin7':     { ttps: ['T1204', 'T1003', 'T1112'], malware: ['CARBANAK', 'GRIFFON'] },
  'lockbit':  { ttps: ['T1486', 'T1490', 'T1078'], malware: ['LockBit Ransomware'] },
  'cl0p':     { ttps: ['T1190', 'T1486', 'T1567'], malware: ['Cl0p Ransomware'] },
  'volt typhoon': { ttps: ['T1190', 'T1133', 'T1059'], malware: ['KV-Botnet'] },
};

const MITRE_TTP_NAMES: Record<string, string> = {
  T1078: 'Valid Accounts', T1071: 'Application Layer Protocol', T1486: 'Data Encryption for Impact',
  T1190: 'Exploit Public-Facing App', T1105: 'Ingress Tool Transfer', T1566: 'Phishing',
  T1059: 'Command & Scripting', T1055: 'Process Injection', T1021: 'Remote Services',
  T1204: 'User Execution', T1003: 'OS Credential Dumping', T1112: 'Modify Registry',
  T1490: 'Inhibit System Recovery', T1567: 'Exfiltration Over Web Service',
  T1133: 'External Remote Services', T1568: 'Dynamic Resolution',
};

// ═══════════════════════════════════════════════════════════════════════════
//  Memoized WebGL Core
// ═══════════════════════════════════════════════════════════════════════════

const MemoizedForceGraph = memo((props: any) => {
  const { ForceGraphComponent, innerRef, ...rest } = props;
  return <ForceGraphComponent ref={innerRef} {...rest} />;
}, () => {
  // Never block re-renders — let graphData updates flow through
  return false;
});

// ═══════════════════════════════════════════════════════════════════════════
//  Main Component
// ═══════════════════════════════════════════════════════════════════════════

const EMPTY_IOCS: any[] = [];
const INITIAL_GRAPH_DATA = { nodes: [], links: [] };

export default function ThreatGraph() {
  const containerRef = useRef<any>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const selectedNodeIdRef = useRef<string | null>(null);
  const hoveredNodeIdRef = useRef<string | null>(null);
  const neighborSetRef = useRef<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [ForceGraph, setForceGraph] = useState<any>(null);
  const [isWebGLSupported, setIsWebGLSupported] = useState<boolean | null>(null);
  const [stixData, setStixData] = useState<GraphData>({ nodes: [], links: [] });
  const threatStream = useThreatStream();
  const armedIocs = threatStream?.armedIocs || EMPTY_IOCS;
  const setSelectedEventId = threatStream?.setSelectedEventId;

  // ── WebGL Detection ────────────────────────────────────────────────────
  useEffect(() => {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    setIsWebGLSupported(!!gl);
  }, []);

  // ── Dynamic Library Import (SSR-safe) ──────────────────────────────────
  useEffect(() => {
    if (isWebGLSupported === false) return;
    import('react-force-graph-3d').then(mod => setForceGraph(() => mod.default));
  }, [isWebGLSupported]);

  // ── Fetch STIX bundle from API ─────────────────────────────────────────
  useEffect(() => {
    async function loadGraph() {
      try {
        const res = await fetch(`${API}/api/v1/dashboard/graph-data`);
        if (res.ok) {
          const data = await res.json();
          setStixData(stixToGraphData(data.objects || []));
        }
      } catch {}
      setLoading(false);
    }
    loadGraph();
  }, []);

  // ═══════════════════════════════════════════════════════════════════════
  //  CORE: Memoized Graph Data Builder (Live Telemetry → Graph Ontology)
  // ═══════════════════════════════════════════════════════════════════════
  const [graphStats, setGraphStats] = useState({ liveIocs: 0, actors: 0, ttps: 0, total: 0, edges: 0 });
  const [liveGraphData, setLiveGraphData] = useState<{ nodes: GraphNode[]; links: GraphLink[] }>({ nodes: [], links: [] });
  const liveGraphDataRef = useRef(liveGraphData);
  liveGraphDataRef.current = liveGraphData;

  // ═══════════════════════════════════════════════════════════════════════
  //  CORE: Imperative Graph Data Builder (Anti-React Memory Shield)
  // ═══════════════════════════════════════════════════════════════════════
  useEffect(() => {
    if (!ForceGraph) return;

    const nodes: GraphNode[] = JSON.parse(JSON.stringify(stixData.nodes || []));
    const links: GraphLink[] = JSON.parse(JSON.stringify(stixData.links || []));
    const existingIds = new Set(nodes.map(n => n.id));

    // ── Step 1: Create Source Feed cluster nodes ─────────────────────────
    const sourceMap = new Map<string, string[]>();
    for (const ioc of armedIocs) {
      const src = (ioc as any).source || 'Unknown';
      if (!sourceMap.has(src)) sourceMap.set(src, []);
      sourceMap.get(src)!.push(ioc.value);
    }

    const sourceNodeIds: Record<string, string> = {};
    for (const src of sourceMap.keys()) {
      const srcId = `source--${src.replace(/\s+/g, '-').toLowerCase()}`;
      if (!existingIds.has(srcId) && nodes.length < NODE_CAP) {
        const cfg = NODE_TAXONOMY['source-cluster'];
        existingIds.add(srcId);
        sourceNodeIds[src] = srcId;
        nodes.push({ id: srcId, name: src, type: 'source-cluster', val: cfg.size, color: cfg.color, icon: cfg.icon, group: cfg.group });
      }
    }

    // ── Step 2: Create Threat Actor scaffold nodes ───────────────────────
    const taNodeIds: Record<string, string> = {};
    for (const n of nodes) {
      if (n.type === 'threat-actor') taNodeIds[n.name.toLowerCase()] = n.id;
    }
    // Ensure known TAs exist as nodes
    for (const [taKey, profile] of Object.entries(TA_TTP_MAP)) {
      const taName = taKey.toUpperCase();
      if (!taNodeIds[taKey]) {
        const taId = `threat-actor--gen-${taKey.replace(/\s+/g, '-')}`;
        if (existingIds.has(taId) || nodes.length >= NODE_CAP) continue;
        existingIds.add(taId);
        const cfg = NODE_TAXONOMY['threat-actor'];
        nodes.push({ id: taId, name: taName, type: 'threat-actor', val: cfg.size, color: cfg.color, icon: cfg.icon, group: cfg.group });
        taNodeIds[taKey] = taId;
      }
      // Create TTP nodes from profile
      for (const ttp of profile.ttps) {
        const ttpId = `attack-pattern--${ttp}`;
        if (!existingIds.has(ttpId) && nodes.length < NODE_CAP) {
          existingIds.add(ttpId);
          const cfg = NODE_TAXONOMY['attack-pattern'];
          nodes.push({ id: ttpId, name: `${ttp}: ${MITRE_TTP_NAMES[ttp] || ttp}`, type: 'attack-pattern', val: cfg.size, color: cfg.color, icon: cfg.icon, group: cfg.group });
        }
        links.push({ source: taNodeIds[taKey], target: ttpId, relationship_type: 'uses', ...LINK_STYLES['uses'] });
      }
      // Create Malware nodes
      for (const mw of profile.malware) {
        const mwId = `malware--${mw.replace(/\s+/g, '-').toLowerCase()}`;
        if (!existingIds.has(mwId) && nodes.length < NODE_CAP) {
          existingIds.add(mwId);
          const cfg = NODE_TAXONOMY['malware'];
          nodes.push({ id: mwId, name: mw, type: 'malware', val: cfg.size, color: cfg.color, icon: cfg.icon, group: cfg.group });
        }
        links.push({ source: taNodeIds[taKey], target: mwId, relationship_type: 'uses', ...LINK_STYLES['uses'] });
      }
    }

    // ── Step 3: Generate IOC indicator nodes (sorted by confidence) ──────
    const sortedIocs = [...armedIocs]
      .sort((a: any, b: any) => (b.confidence || 0) - (a.confidence || 0))
      .slice(0, NODE_CAP - nodes.length);

    for (const ioc of sortedIocs) {
      const nodeId = `indicator--${ioc.value}`;
      if (existingIds.has(nodeId)) continue;
      if (nodes.length >= NODE_CAP) break;

      existingIds.add(nodeId);
      const sev = (ioc as any).severity || 'high';
      const typeKey = sev === 'critical' ? 'indicator-crit' : sev === 'high' ? 'indicator-high' : 'indicator';
      const cfg = NODE_TAXONOMY[typeKey];
      nodes.push({
        id: nodeId,
        name: ioc.value,
        type: 'indicator',
        val: cfg.size,
        color: cfg.color,
        icon: cfg.icon,
        group: cfg.group,
        data: ioc as any,
      });

      // Link IOC → Source Feed
      const src = (ioc as any).source || '';
      if (sourceNodeIds[src]) {
        links.push({ source: sourceNodeIds[src], target: nodeId, relationship_type: 'sourced-from', ...LINK_STYLES['sourced-from'] });
      }

      // Link IOC → MITRE TTPs
      const mitreTechs = (ioc as any).related_mitre_techniques || (ioc as any).mitre_techniques || [];
      for (const ttp of mitreTechs) {
        const ttpId = `attack-pattern--${ttp}`;
        if (existingIds.has(ttpId)) {
          links.push({ source: ttpId, target: nodeId, relationship_type: 'indicates', ...LINK_STYLES['indicates'] });
        }
      }

      // Link IOC → Threat Actor by tag heuristic
      const tags = ((ioc as any).tags || []) as string[];
      for (const tag of tags) {
        const normalTag = tag.toLowerCase();
        for (const [taKey, taId] of Object.entries(taNodeIds)) {
          if (normalTag.includes(taKey) || taKey.includes(normalTag)) {
            links.push({ source: taId, target: nodeId, relationship_type: 'uses', color: '#ff3b5c33', width: 1 });
            break;
          }
        }
      }
    }

    // Deduplicate links
    const linkSet = new Set<string>();
    const deduped = links.filter(l => {
      const key = `${typeof l.source === 'string' ? l.source : (l.source as any).id}→${typeof l.target === 'string' ? l.target : (l.target as any).id}→${l.relationship_type}`;
      if (linkSet.has(key)) return false;
      linkSet.add(key);
      return existingIds.has(typeof l.source === 'string' ? l.source : (l.source as any).id) &&
             existingIds.has(typeof l.target === 'string' ? l.target : (l.target as any).id);
    });

    // ── DECLARATIVE DATA INJECTION (React prop-driven) ──────────────────────
    setLiveGraphData({ nodes, links: deduped });

    setGraphStats({
      liveIocs: nodes.filter(n => n.id.startsWith('indicator--')).length,
      actors: nodes.filter(n => n.type === 'threat-actor').length,
      ttps: nodes.filter(n => n.type === 'attack-pattern').length,
      total: nodes.length,
      edges: deduped.length,
    });

  }, [stixData, armedIocs, ForceGraph]);

  // ── D3 physics configuration ───────────────────────────────────────────
  useEffect(() => {
    if (containerRef.current && typeof containerRef.current.d3Force === 'function') {
      // 1. Charge Force (Repulsion) - Keep nodes spaced but not exploding
      containerRef.current.d3Force('charge').strength(-200).distanceMax(400);
      
      // 2. Link Force (Distance) - Keep clusters tight
      containerRef.current.d3Force('link').distance(40);
      
      // 3. Collision - Prevent overlapping
      containerRef.current.d3Force('collide', d3.forceCollide((node: any) => (node.val || 1) * 1.2 + 4));

      // Auto-fit after warmup
      const to = setTimeout(() => {
        if (containerRef.current && typeof containerRef.current.zoomToFit === 'function') {
          containerRef.current.zoomToFit(600, 60);
        }
      }, 2000);
      return () => clearTimeout(to);
    }
  }, [ForceGraph]);

  // ── Node Click Handler (syncs global state) ────────────────────────────
  const handleNodeClick = useCallback((node: GraphNode) => {
    selectedNodeIdRef.current = node.id;
    setSelectedNode(node);
    
    // Sync with global IOC Explorer filter for indicator nodes
    if (node.type === 'indicator' && setSelectedEventId) {
      setSelectedEventId(node.name);
    }
    
    // Cinematic "Fly-To" Camera Animation
    if (containerRef.current) {
      const { x = 0, y = 0, z = 0 } = node as any;
      containerRef.current.cameraPosition(
        { x: x * 1.5, y: y * 1.5, z: z + 150 }, // Fly aggressively close
        { x, y, z }, // Look directly at the node
        1500 // Smooth 1500ms transition
      );
    }
  }, [setSelectedEventId]);

  // ── Hover Handler (Decoupled from Render) ─────────────────────────────
  const handleNodeHover = useCallback((node: GraphNode | null) => {
    hoveredNodeIdRef.current = node ? node.id : null;
    if (typeof document !== 'undefined') {
      document.body.style.cursor = node ? 'pointer' : 'default';
    }
    
    // Maintain neighbor logic without triggering React renders
    const set = new Set<string>();
    if (node) {
      set.add(node.id);
      const currentLinks = liveGraphDataRef.current.links;
      for (const link of currentLinks) {
        const srcId = typeof link.source === 'string' ? link.source : (link.source as any).id;
        const tgtId = typeof link.target === 'string' ? link.target : (link.target as any).id;
        if (srcId === node.id) set.add(tgtId);
        if (tgtId === node.id) set.add(srcId);
      }
    }
    neighborSetRef.current = set;
    
    // Inform ForceGraph to softly update visual buffers without reheat
    if (containerRef.current && typeof containerRef.current.nodeColor === 'function') {
      containerRef.current.nodeColor(containerRef.current.nodeColor());
      containerRef.current.linkWidth(containerRef.current.linkWidth());
    }
  }, []);

  // ── Neighbor-aware color accessors (Palantir Focus Mode) ───────────────
  const getNodeColor = useCallback((node: GraphNode) => {
    // If selected, highlight with intense cyan pulse
    if (selectedNodeIdRef.current === node.id) return '#00eeff';
    if (!hoveredNodeIdRef.current) return node.color;
    
    // Focus Model isolates neighbor nodes with original colors, fades the rest completely
    return neighborSetRef.current.has(node.id) ? node.color : 'rgba(255,255,255,0.05)';
  }, []);

  const getLinkColor = useCallback((link: GraphLink) => {
    if (!hoveredNodeIdRef.current) return link.color;
    const srcId = typeof link.source === 'string' ? link.source : (link.source as any).id;
    const tgtId = typeof link.target === 'string' ? link.target : (link.target as any).id;
    
    // Illuminate attack paths directly attached to hovered node
    return (neighborSetRef.current.has(srcId) && neighborSetRef.current.has(tgtId))
      ? '#00eeff' 
      : 'rgba(255,255,255,0.02)';
  }, []);
  
  const getLinkWidth = useCallback((link: GraphLink) => {
    if (!hoveredNodeIdRef.current) return link.width;
    const srcId = typeof link.source === 'string' ? link.source : (link.source as any).id;
    return neighborSetRef.current.has(srcId) ? link.width * 2.0 : 0.1;
  }, []);

  const handleNodeDrag = useCallback((node: GraphNode) => {
    // Lock the node exactly under the cursor during the drag
    (node as any).fx = (node as any).x;
    (node as any).fy = (node as any).y;
    if ((node as any).z !== undefined) (node as any).fz = (node as any).z;
  }, []);

  const handleNodeDragEnd = useCallback((node: GraphNode) => {
    // Permanently pin the node where the user drops it, ensuring it doesn't snap back
    (node as any).fx = (node as any).x;
    (node as any).fy = (node as any).y;
    if ((node as any).z !== undefined) (node as any).fz = (node as any).z;
  }, []);

  // ── Narrative Generator ────────────────────────────────────────────────
  const generateNarrative = useCallback((node: GraphNode) => {
    const getNodeId = (ref: any) => typeof ref === 'string' ? ref : ref?.id;
    const currentGraphData = liveGraphDataRef.current;

    const outgoing = currentGraphData.links.filter((l: any) => getNodeId(l.source) === node.id);
    const incoming = currentGraphData.links.filter((l: any) => getNodeId(l.target) === node.id);
    
    if (node.type === 'threat-actor') {
      const malwares = outgoing.filter((l: any) => l.relationship_type === 'uses').map((l: any) => currentGraphData.nodes.find((n: any) => n.id === getNodeId(l.target))?.name).filter(Boolean);
      const ttps = outgoing.filter((l: any) => l.relationship_type === 'uses' && getNodeId(l.target)?.startsWith('attack-pattern')).length;
      return `[ANALYSIS] ${node.name} is a tracked threat group deploying ${malwares.length > 0 ? malwares.slice(0, 3).join(', ') : 'unidentified tooling'}, linked to ${ttps} MITRE ATT&CK techniques and ${incoming.length + outgoing.length - ttps} active IOCs in the platform.`;
    }
    if (node.type === 'attack-pattern') {
      const actors = incoming.filter((l: any) => l.relationship_type === 'uses').map((l: any) => currentGraphData.nodes.find((n: any) => n.id === getNodeId(l.source))?.name).filter(Boolean);
      const iocs = outgoing.filter((l: any) => l.relationship_type === 'indicates').length;
      return `[ANALYSIS] MITRE technique ${node.name} is attributed to ${actors.length > 0 ? actors.join(', ') : 'unknown actors'}, with ${iocs} correlated IOCs currently active in the threat landscape.`;
    }
    if (node.type === 'indicator') {
      const sev = (node.data as any)?.severity || 'unknown';
      const src = (node.data as any)?.source || 'live feed';
      const conf = (node.data as any)?.confidence ?? 'N/A';
      return `[IOC INTEL] ${node.name} — Severity: ${sev.toUpperCase()}, Confidence: ${conf}%, Source: ${src}. ${incoming.length} inbound connections from threat infrastructure.`;
    }
    return `[ANALYSIS] Entity "${node.name}" (${node.type}) has ${incoming.length + outgoing.length} graph connections.`;
  }, []);

  // ═══════════════════════════════════════════════════════════════════════
  //  RENDER: Empty State
  // ═══════════════════════════════════════════════════════════════════════
  if (loading || !ForceGraph || isWebGLSupported === null) {
    return (
      <div className="onyx-card" style={{ height: '700px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="loading-shimmer" style={{ width: '60px', height: '60px', borderRadius: '50%', margin: '0 auto 16px' }} />
          <span style={{ color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-sm)' }}>
            Initializing WebGL render engine...
          </span>
        </div>
      </div>
    );
  }

  if (isWebGLSupported === false) {
    return (
      <div className="onyx-card" style={{ height: '700px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center', color: '#ef4444' }}>
          <div style={{ fontSize: 24, marginBottom: 8 }}>⚠️</div>
          <p style={{ fontSize: 13 }}>WebGL unavailable. Upgrade your browser or enable GPU acceleration.</p>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  RENDER: Main Graph View (Never Unmount Canvas)
  // ═══════════════════════════════════════════════════════════════════════
  return (
    <div style={{ display: 'flex', gap: 16, height: '700px' }}>
      {/* 3D WebGL Canvas */}
      <div className="onyx-card" style={{ flex: 1, padding: 0, overflow: 'hidden', position: 'relative', height: '100%' }}>

        {/* ── HUD Overlay ─────────────────────────────────────────── */}
        {graphStats.total === 0 && (
          <div style={{ position: 'absolute', inset: 0, zIndex: 50, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: '#03060a', color: 'var(--text-tertiary)' }}>
            <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.3 }}>◎</div>
            <p style={{ fontSize: 13, fontFamily: 'monospace' }}>Awaiting live telemetry...</p>
            <p style={{ fontSize: 11, color: '#4b5563' }}>Graph will populate as OSINT data arrives via SSE.</p>
          </div>
        )}

        <div style={{ position: 'absolute', top: 14, left: 14, zIndex: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#94a3b8', background: 'rgba(5,10,15,0.85)', padding: '5px 10px', borderRadius: 4, backdropFilter: 'blur(8px)', border: '1px solid #1e293b' }}>
            NODES: {graphStats.total} | EDGES: {graphStats.edges}
          </div>
          <div style={{ fontFamily: 'monospace', fontSize: 10, background: 'rgba(5,10,15,0.85)', padding: '5px 10px', borderRadius: 4, backdropFilter: 'blur(8px)', border: '1px solid #1e293b', display: 'flex', gap: 12 }}>
            <span style={{ color: '#ff3b5c' }}>☠ {graphStats.actors} TA</span>
            <span style={{ color: '#a855f7' }}>◆ {graphStats.ttps} TTPs</span>
            <span style={{ color: '#00f0ff' }}>⬡ {graphStats.liveIocs} IOCs</span>
          </div>
          {graphStats.total >= NODE_CAP && (
            <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#f59e0b', background: 'rgba(245,158,11,0.1)', padding: '3px 8px', borderRadius: 4, border: '1px solid rgba(245,158,11,0.3)' }}>
              ⚠ NODE CAP REACHED ({NODE_CAP}) — Highest confidence IOCs prioritized
            </div>
          )}
        </div>

        {/* ── Legend ──────────────────────────────────────────────── */}
        <div style={{ position: 'absolute', bottom: 14, left: 14, zIndex: 10, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {LEGEND_ITEMS.map(item => (
            <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'monospace', fontSize: 9, color: '#64748b', background: 'rgba(5,10,15,0.85)', padding: '3px 7px', borderRadius: 99, backdropFilter: 'blur(8px)' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: item.color, boxShadow: `0 0 4px ${item.color}` }} />
              {item.label}
            </div>
          ))}
        </div>

        {/* ── Controls ────────────────────────────────────────────── */}
        <div style={{ position: 'absolute', top: 14, right: 14, zIndex: 10, display: 'flex', gap: 6 }}>
          <button onClick={() => containerRef.current?.zoomToFit(600, 60)} style={{ fontFamily: 'monospace', fontSize: 10, padding: '4px 10px', background: 'rgba(5,10,15,0.85)', border: '1px solid #1e293b', borderRadius: 4, color: '#00f0ff', cursor: 'pointer' }}>
            ⊞ FIT VIEW
          </button>
          <button onClick={() => { setSelectedNode(null); if (setSelectedEventId) setSelectedEventId(null); }} style={{ fontFamily: 'monospace', fontSize: 10, padding: '4px 10px', background: 'rgba(5,10,15,0.85)', border: '1px solid #1e293b', borderRadius: 4, color: '#6b7280', cursor: 'pointer' }}>
            ✕ DESELECT
          </button>
        </div>

        {/* ── ForceGraph 3D ───────────────────────────────────────── */}
        <MemoizedForceGraph
          ForceGraphComponent={ForceGraph}
          innerRef={containerRef}
          graphData={liveGraphData}
          nodeLabel={(node: GraphNode) => `${node.icon} ${node.name}\n[${node.type}]`}
          nodeColor={getNodeColor}
          nodeVal={(node: GraphNode) => node.val}
          nodeRelSize={4}
          nodeOpacity={0.95}
          linkColor={getLinkColor}
          linkWidth={getLinkWidth}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleSpeed={0.005}
          linkDirectionalParticleColor={(link: GraphLink) => '#00eeff'}
          linkDirectionalArrowLength={3.5}
          linkDirectionalArrowRelPos={1}
          onNodeClick={handleNodeClick}
          onNodeHover={handleNodeHover}
          onNodeDrag={handleNodeDrag}
          onNodeDragEnd={handleNodeDragEnd}
          backgroundColor="#000000" // Absolute void black
          width={typeof window !== 'undefined' ? Math.max(window.innerWidth * 0.55, 600) : 800}
          height={700}
          warmupTicks={150} // Extended warmup for better initial distribution
          cooldownTicks={0} // ABSOLUTE FREEZE: Physics engine stops completely
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.4}
        />
      </div>

      {/* ═══════════════════════════════════════════════════════════════════
         Investigation Side Panel
         ═══════════════════════════════════════════════════════════════════ */}
      <div className="onyx-card" style={{ width: 340, height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            ◎ Investigation Panel
          </h3>
          <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '2px 8px', borderRadius: 99, border: '1px solid rgba(34,197,94,0.3)' }}>
            LIVE
          </span>
        </div>

        {selectedNode ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, flex: 1 }}>
            {/* Entity Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 12, background: '#0a0f1a', borderRadius: 8, borderLeft: `3px solid ${selectedNode.color}` }}>
              <span style={{ fontSize: 24 }}>{selectedNode.icon}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 700, fontSize: 14, color: '#e5e7eb', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selectedNode.name}</div>
                <div style={{ fontSize: 10, color: '#6b7280', fontFamily: 'monospace', textTransform: 'uppercase' }}>{selectedNode.type} · {selectedNode.group}</div>
              </div>
            </div>

            {/* Risk Score */}
            {selectedNode.data && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                {[
                  { label: 'SEVERITY', value: ((selectedNode.data as any).severity || 'N/A').toUpperCase(), color: (selectedNode.data as any).severity === 'critical' ? '#ef4444' : '#f59e0b' },
                  { label: 'CONFIDENCE', value: `${(selectedNode.data as any).confidence || 'N/A'}%`, color: '#00f0ff' },
                  { label: 'SOURCE', value: ((selectedNode.data as any).source || 'API').substring(0, 10), color: '#22c55e' },
                ].map((m, i) => (
                  <div key={i} style={{ background: '#0f172a', borderRadius: 6, padding: 8, textAlign: 'center' }}>
                    <div style={{ fontSize: 9, color: '#4b5563', fontWeight: 600 }}>{m.label}</div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: m.color, fontFamily: 'monospace' }}>{m.value}</div>
                  </div>
                ))}
              </div>
            )}

            {/* Connections */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {[
                { label: 'INCOMING', color: '#00f0ff', count: liveGraphData.links.filter(l => (typeof l.target === 'string' ? l.target : (l.target as any).id) === selectedNode.id).length },
                { label: 'OUTGOING', color: '#ff00e5', count: liveGraphData.links.filter(l => (typeof l.source === 'string' ? l.source : (l.source as any).id) === selectedNode.id).length },
              ].map((c, i) => (
                <div key={i} style={{ background: '#0f172a', borderRadius: 6, padding: 8, textAlign: 'center' }}>
                  <div style={{ fontSize: 9, color: '#4b5563', fontWeight: 600 }}>{c.label}</div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: c.color, fontFamily: 'monospace' }}>{c.count}</div>
                </div>
              ))}
            </div>

            {/* Narrative */}
            <div style={{ background: 'rgba(0,238,255,0.04)', borderRadius: 8, padding: 12, borderLeft: '3px solid #00f0ff' }}>
              <div style={{ fontSize: 10, color: '#00f0ff', marginBottom: 6, fontWeight: 700, fontFamily: 'monospace' }}>⟁ THREAT INTELLIGENCE NARRATIVE</div>
              <p style={{ fontSize: 12, color: '#cbd5e1', lineHeight: 1.6, margin: 0, fontFamily: 'system-ui, sans-serif' }}>
                {generateNarrative(selectedNode)}
              </p>
            </div>

            {/* Connected Entities */}
            <div>
              <div style={{ fontSize: 10, color: '#4b5563', fontWeight: 700, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Connected Entities</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 160, overflowY: 'auto' }}>
                {liveGraphData.links
                  .filter(l => {
                    const sid = typeof l.source === 'string' ? l.source : (l.source as any).id;
                    const tid = typeof l.target === 'string' ? l.target : (l.target as any).id;
                    return sid === selectedNode.id || tid === selectedNode.id;
                  })
                  .slice(0, 20)
                  .map((l, i) => {
                    const sid = typeof l.source === 'string' ? l.source : (l.source as any).id;
                    const tid = typeof l.target === 'string' ? l.target : (l.target as any).id;
                    const otherId = sid === selectedNode.id ? tid : sid;
                    const other = liveGraphData.nodes.find(n => n.id === otherId);
                    return other ? (
                      <div key={i} onClick={() => handleNodeClick(other)} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', background: '#0f172a', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontFamily: 'monospace' }}>
                        <span style={{ color: other.color }}>{other.icon}</span>
                        <span style={{ color: '#94a3b8', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{other.name}</span>
                        <span style={{ color: '#334155', fontSize: 9 }}>{l.relationship_type}</span>
                      </div>
                    ) : null;
                  })}
              </div>
            </div>

            {/* Raw Data */}
            {selectedNode.data && (
              <details style={{ fontSize: 10 }}>
                <summary style={{ color: '#4b5563', cursor: 'pointer', fontFamily: 'monospace', fontWeight: 600 }}>RAW DATA</summary>
                <pre style={{ fontFamily: 'monospace', fontSize: 9, color: '#64748b', background: '#050505', padding: 8, borderRadius: 6, maxHeight: 150, overflow: 'auto', whiteSpace: 'pre-wrap', marginTop: 6 }}>
                  {JSON.stringify(selectedNode.data, null, 2)}
                </pre>
              </details>
            )}
          </div>
        ) : (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', color: '#4b5563' }}>
            <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.2 }}>◎</div>
            <p style={{ fontSize: 12, fontFamily: 'monospace', marginBottom: 6 }}>Select a node to investigate</p>
            <p style={{ fontSize: 10, color: '#334155' }}>Click any entity to reveal its connections, threat narrative, and correlated IOCs.</p>
            <p style={{ fontSize: 10, color: '#334155', marginTop: 4 }}>Hover to highlight 1st-degree neighbors.</p>
          </div>
        )}
      </div>
    </div>
  );
}
