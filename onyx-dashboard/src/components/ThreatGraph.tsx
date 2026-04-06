'use client';

import { useEffect, useRef, useState, useMemo, useCallback } from 'react';

/*
 * ONYX CTI — 3D STIX Threat Graph
 * Force-directed 3D graph visualization of STIX relationships using three.js.
 * 
 * Pattern source: OpenCTI's react-force-graph-3d usage pattern —
 * STIX SDOs as nodes, SROs as links, with type-based coloring and
 * interactive selection. Enhanced with WebGL particle effects,
 * bloom glow, and animated link flow.
 *
 * Uses dynamic import for react-force-graph-3d (heavy three.js dependency).
 */

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// STIX type → visual configuration (OpenCTI color mapping enhanced)
const STIX_NODE_CONFIG: Record<string, { color: string; shape: string; size: number; icon: string }> = {
  'threat-actor':    { color: '#ff3b5c', shape: 'sphere',    size: 14, icon: '☠' },
  'malware':         { color: '#ff6b35', shape: 'octahedron', size: 12, icon: '☣' },
  'indicator':       { color: '#00f0ff', shape: 'sphere',    size: 8,  icon: '⬡' },
  'campaign':        { color: '#ff00e5', shape: 'sphere',    size: 13, icon: '⚔' },
  'intrusion-set':   { color: '#ff3b5c', shape: 'sphere',    size: 15, icon: '👁' },
  'attack-pattern':  { color: '#ffaa00', shape: 'tetra',     size: 10, icon: '◆' },
  'vulnerability':   { color: '#ff6b35', shape: 'sphere',    size: 9,  icon: '⚠' },
  'tool':            { color: '#00ff88', shape: 'cube',      size: 8,  icon: '🔧' },
  'identity':        { color: '#8b95a8', shape: 'sphere',    size: 7,  icon: '●' },
  'report':          { color: '#a78bfa', shape: 'sphere',    size: 10, icon: '📋' },
  'infrastructure':  { color: '#14b8a6', shape: 'cube',      size: 9,  icon: '🖥' },
  'location':        { color: '#06b6d4', shape: 'sphere',    size: 7,  icon: '📍' },
};

// Relationship type → link style
const LINK_STYLES: Record<string, { color: string; width: number; dash: boolean }> = {
  'uses':                { color: '#ff3b5c88', width: 2, dash: false },
  'targets':             { color: '#ff6b3588', width: 2, dash: false },
  'indicates':           { color: '#00f0ff88', width: 1.5, dash: false },
  'attributed-to':       { color: '#ff00e588', width: 2.5, dash: false },
  'related-to':          { color: '#8b95a844', width: 1, dash: true },
  'mitigates':           { color: '#00ff8888', width: 1.5, dash: true },
  'communicates-with':   { color: '#ffaa0088', width: 1.5, dash: false },
  'delivers':            { color: '#ff3b5c88', width: 2, dash: false },
};

interface GraphNode {
  id: string;
  name: string;
  type: string;
  val: number;
  color: string;
  icon: string;
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

// Transform STIX objects to graph data (OpenCTI pattern)
function stixToGraphData(objects: any[]): GraphData {
  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];
  const nodeIds = new Set<string>();

  for (const obj of objects) {
    if (obj.type === 'relationship' || obj.type === 'sighting') {
      // SRO → link
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
      // SDO → node
      if (nodeIds.has(obj.id)) continue;
      nodeIds.add(obj.id);
      const config = STIX_NODE_CONFIG[obj.type] || { color: '#8b95a8', shape: 'sphere', size: 6, icon: '●' };
      nodes.push({
        id: obj.id,
        name: obj.name || obj.value || obj.id.split('--')[0],
        type: obj.type,
        val: config.size,
        color: config.color,
        icon: config.icon,
        data: obj,
      });
    }
  }

  // Filter links where both source and target exist
  const validLinks = links.filter(l => nodeIds.has(l.source) && nodeIds.has(l.target));
  return { nodes, links: validLinks };
}

export default function ThreatGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [ForceGraph, setForceGraph] = useState<any>(null);

  // Dynamically import react-force-graph-3d (SSR incompatible)
  useEffect(() => {
    import('react-force-graph-3d').then(mod => setForceGraph(() => mod.default));
  }, []);

  // Fetch STIX data from API
  useEffect(() => {
    async function loadGraph() {
      try {
        const res = await fetch(`${API}/api/v1/dashboard/graph-data`);
        if (res.ok) {
          const data = await res.json();
          setGraphData(stixToGraphData(data.objects || []));
        } else {
          // Demo data
          setGraphData(getDemoGraphData());
        }
      } catch {
        setGraphData(getDemoGraphData());
      }
      setLoading(false);
    }
    loadGraph();
  }, []);

  const handleNodeClick = useCallback((node: GraphNode) => {
    setSelectedNode(node);
  }, []);

  if (loading || !ForceGraph) {
    return (
      <div className="onyx-card" style={{ height: '600px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="loading-shimmer" style={{ width: '60px', height: '60px', borderRadius: '50%', margin: '0 auto 16px' }} />
          <span style={{ color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-sm)' }}>
            Initializing WebGL render engine...
          </span>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', gap: 'var(--space-lg)' }}>
      {/* Graph Canvas */}
      <div className="onyx-card" style={{ flex: 1, padding: 0, overflow: 'hidden', position: 'relative', height: '600px' }}>
        {/* HUD Overlay */}
        <div style={{ position: 'absolute', top: '16px', left: '16px', zIndex: 10, display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)', background: 'var(--onyx-bg-glass)', padding: '6px 12px', borderRadius: 'var(--radius-sm)', backdropFilter: 'blur(8px)' }}>
            NODES: {graphData.nodes.length} | EDGES: {graphData.links.length}
          </div>
        </div>

        {/* Legend */}
        <div style={{ position: 'absolute', bottom: '16px', left: '16px', zIndex: 10, display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
          {Object.entries(STIX_NODE_CONFIG).slice(0, 8).map(([type, cfg]) => (
            <div key={type} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-tertiary)', background: 'var(--onyx-bg-glass)', padding: '3px 8px', borderRadius: 'var(--radius-full)', backdropFilter: 'blur(8px)' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: cfg.color }} />
              {type}
            </div>
          ))}
        </div>

        <ForceGraph
          ref={containerRef}
          graphData={graphData}
          nodeLabel={(node: GraphNode) => `${node.icon} ${node.name}\n[${node.type}]`}
          nodeColor={(node: GraphNode) => node.color}
          nodeVal={(node: GraphNode) => node.val}
          nodeRelSize={5}
          linkColor={(link: GraphLink) => link.color}
          linkWidth={(link: GraphLink) => link.width}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={1.5}
          linkDirectionalParticleColor={(link: GraphLink) => link.color.replace('88', 'ff')}
          linkDirectionalArrowLength={4}
          linkDirectionalArrowRelPos={1}
          onNodeClick={handleNodeClick}
          backgroundColor="#06080f"
          width={typeof window !== 'undefined' ? window.innerWidth * 0.6 : 800}
          height={600}
          warmupTicks={50}
          cooldownTicks={100}
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.3}
        />
      </div>

      {/* Node Detail Panel */}
      <div className="onyx-card" style={{ width: '320px', height: '600px', overflowY: 'auto' }}>
        <h3 style={{ fontSize: 'var(--font-size-base)', fontWeight: 700, marginBottom: 'var(--space-md)', display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
          ◎ Entity Details
        </h3>
        {selectedNode ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-md)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
              <span style={{ fontSize: '1.5rem' }}>{selectedNode.icon}</span>
              <div>
                <div style={{ fontWeight: 700, fontSize: 'var(--font-size-md)' }}>{selectedNode.name}</div>
                <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>{selectedNode.type}</div>
              </div>
            </div>

            <div style={{ background: 'var(--onyx-bg-tertiary)', borderRadius: 'var(--radius-sm)', padding: 'var(--space-md)' }}>
              <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)', marginBottom: '4px' }}>STIX ID</div>
              <div className="ioc-value" style={{ fontSize: '11px', wordBreak: 'break-all' }}>{selectedNode.id}</div>
            </div>

            {/* Connections count */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-sm)' }}>
              <div style={{ background: 'var(--onyx-bg-tertiary)', borderRadius: 'var(--radius-sm)', padding: 'var(--space-sm)', textAlign: 'center' }}>
                <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)' }}>INCOMING</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-lg)', fontWeight: 800, color: 'var(--onyx-cyan)' }}>
                  {graphData.links.filter(l => (typeof l.target === 'string' ? l.target : (l.target as any).id) === selectedNode.id).length}
                </div>
              </div>
              <div style={{ background: 'var(--onyx-bg-tertiary)', borderRadius: 'var(--radius-sm)', padding: 'var(--space-sm)', textAlign: 'center' }}>
                <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)' }}>OUTGOING</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-lg)', fontWeight: 800, color: 'var(--onyx-magenta)' }}>
                  {graphData.links.filter(l => (typeof l.source === 'string' ? l.source : (l.source as any).id) === selectedNode.id).length}
                </div>
              </div>
            </div>

            {/* Raw STIX data */}
            {selectedNode.data && (
              <div>
                <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)', marginBottom: '4px' }}>RAW STIX DATA</div>
                <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-secondary)', background: 'var(--onyx-bg-primary)', padding: 'var(--space-sm)', borderRadius: 'var(--radius-sm)', maxHeight: '200px', overflow: 'auto', whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(selectedNode.data, null, 2)}
                </pre>
              </div>
            )}
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: 'var(--space-xl)', color: 'var(--text-tertiary)' }}>
            <div style={{ fontSize: '2rem', marginBottom: 'var(--space-sm)', opacity: 0.3 }}>◎</div>
            <p style={{ fontSize: 'var(--font-size-sm)' }}>Click a node to inspect its STIX data and relationships.</p>
          </div>
        )}
      </div>
    </div>
  );
}

/* Demo data for when API is not connected */
function getDemoGraphData(): GraphData {
  const nodes: GraphNode[] = [
    { id: 'threat-actor--1', name: 'LockBit 3.0', type: 'threat-actor', val: 14, color: '#ff3b5c', icon: '☠' },
    { id: 'threat-actor--2', name: 'BlackCat/ALPHV', type: 'threat-actor', val: 14, color: '#ff3b5c', icon: '☠' },
    { id: 'threat-actor--3', name: 'Cl0p', type: 'threat-actor', val: 13, color: '#ff3b5c', icon: '☠' },
    { id: 'malware--1', name: 'LockBit Ransomware', type: 'malware', val: 12, color: '#ff6b35', icon: '☣' },
    { id: 'malware--2', name: 'BlackCat Ransomware', type: 'malware', val: 12, color: '#ff6b35', icon: '☣' },
    { id: 'malware--3', name: 'Cobalt Strike', type: 'malware', val: 11, color: '#ff6b35', icon: '☣' },
    { id: 'attack-pattern--1', name: 'T1486: Data Encryption', type: 'attack-pattern', val: 10, color: '#ffaa00', icon: '◆' },
    { id: 'attack-pattern--2', name: 'T1190: Exploit Public App', type: 'attack-pattern', val: 10, color: '#ffaa00', icon: '◆' },
    { id: 'attack-pattern--3', name: 'T1078: Valid Accounts', type: 'attack-pattern', val: 10, color: '#ffaa00', icon: '◆' },
    { id: 'indicator--1', name: '185.220.101.xxx', type: 'indicator', val: 8, color: '#00f0ff', icon: '⬡' },
    { id: 'indicator--2', name: 'abc123...sha256', type: 'indicator', val: 8, color: '#00f0ff', icon: '⬡' },
    { id: 'indicator--3', name: 'evil-domain.onion', type: 'indicator', val: 8, color: '#00f0ff', icon: '⬡' },
    { id: 'vulnerability--1', name: 'CVE-2024-21887', type: 'vulnerability', val: 9, color: '#ff6b35', icon: '⚠' },
    { id: 'campaign--1', name: 'MOVEit Exploitation', type: 'campaign', val: 13, color: '#ff00e5', icon: '⚔' },
    { id: 'tool--1', name: 'Mimikatz', type: 'tool', val: 8, color: '#00ff88', icon: '🔧' },
    { id: 'identity--1', name: 'Healthcare Sector', type: 'identity', val: 7, color: '#8b95a8', icon: '●' },
  ];

  const links: GraphLink[] = [
    { source: 'threat-actor--1', target: 'malware--1', relationship_type: 'uses', color: '#ff3b5c88', width: 2 },
    { source: 'threat-actor--2', target: 'malware--2', relationship_type: 'uses', color: '#ff3b5c88', width: 2 },
    { source: 'threat-actor--1', target: 'attack-pattern--1', relationship_type: 'uses', color: '#ffaa0088', width: 2 },
    { source: 'threat-actor--2', target: 'attack-pattern--1', relationship_type: 'uses', color: '#ffaa0088', width: 2 },
    { source: 'threat-actor--3', target: 'attack-pattern--2', relationship_type: 'uses', color: '#ffaa0088', width: 2 },
    { source: 'malware--1', target: 'indicator--1', relationship_type: 'indicates', color: '#00f0ff88', width: 1.5 },
    { source: 'malware--2', target: 'indicator--2', relationship_type: 'indicates', color: '#00f0ff88', width: 1.5 },
    { source: 'malware--1', target: 'indicator--3', relationship_type: 'indicates', color: '#00f0ff88', width: 1.5 },
    { source: 'threat-actor--1', target: 'identity--1', relationship_type: 'targets', color: '#ff6b3588', width: 2 },
    { source: 'threat-actor--3', target: 'campaign--1', relationship_type: 'attributed-to', color: '#ff00e588', width: 2.5 },
    { source: 'campaign--1', target: 'vulnerability--1', relationship_type: 'targets', color: '#ff6b3588', width: 2 },
    { source: 'threat-actor--1', target: 'tool--1', relationship_type: 'uses', color: '#00ff8888', width: 1.5 },
    { source: 'threat-actor--2', target: 'tool--1', relationship_type: 'uses', color: '#00ff8888', width: 1.5 },
    { source: 'malware--3', target: 'attack-pattern--3', relationship_type: 'uses', color: '#ffaa0088', width: 1.5 },
    { source: 'threat-actor--1', target: 'malware--3', relationship_type: 'uses', color: '#ff3b5c88', width: 2 },
  ];

  return { nodes, links };
}
