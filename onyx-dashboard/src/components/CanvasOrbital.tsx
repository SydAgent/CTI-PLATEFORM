'use client';

/**
 * CanvasOrbital — D3 force-simulation orbital graph.
 *
 * Orbit 0 (r=0):   actor hub
 * Orbit 1 (r=120): tools / campaigns
 * Orbit 2 (r=220): MITRE techniques (TTPs)
 * Orbit 3 (r=320): IoCs (sampled, max 24)
 *
 * D3 lifecycle contract:
 *  - `draw` is a stable function (no deps on reactive state).
 *    Reactive values (selectedNodeId, densityLevel) are read via refs so the
 *    simulation's tick handler never holds a stale closure.
 *  - `simulation.stop()` is called in every useEffect cleanup that starts one.
 *    This prevents CPU saturation after component unmount.
 *  - ResizeObserver fires render on container resize.
 *
 * Zustand selectors are granular: each subscription reads one slice so the
 * graph does not re-render when unrelated store slices (e.g. brushedTimeRange)
 * change.
 */

import React, { useEffect, useRef, useCallback, useMemo } from 'react';
import * as d3 from 'd3';
import { useActorDetailStore, DensityLevel } from '@/lib/actorDetailStore';

// ─── Types ────────────────────────────────────────────────────────────────────

interface OrbitalNode {
  id: string;
  label: string;
  type: 'actor' | 'tool' | 'ttp' | 'ioc';
  orbit: 0 | 1 | 2 | 3;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}

interface OrbitalLink {
  source: string | OrbitalNode;
  target: string | OrbitalNode;
  strength: number;
}

interface IoCSummary {
  id: string;
  type: string;
  value: string;
  decay_state?: string | null;
}

export interface CanvasOrbitalProps {
  actorId: string;
  actorName: string;
  techniques: string[];
  tools: string[];
  iocs?: IoCSummary[];
  densityLevel?: DensityLevel;
  width?: number;
  height?: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const ORBIT_RADII = [0, 120, 220, 320] as const;
const MAX_TOOLS = 8;
const MAX_TTPS = 14;
const MAX_IOCS = 24;

const TYPE_COLORS: Record<OrbitalNode['type'], string> = {
  actor: '#ff3b5c',
  tool:  '#00eeff',
  ttp:   '#a855f7',
  ioc:   '#f59e0b',
};

const TYPE_RADIUS: Record<OrbitalNode['type'], number> = {
  actor: 18, tool: 9, ttp: 8, ioc: 5,
};

const TYPE_ICONS: Record<OrbitalNode['type'], string> = {
  actor: '☠', tool: '⬡', ttp: '⚔', ioc: '◎',
};

const DECAY_STATE_COLORS: Record<string, string> = {
  valid: '#22c55e', degrading: '#eab308', stale: '#f97316', obsolete: '#ef4444',
};

// ─── Build graph data ─────────────────────────────────────────────────────────

function buildGraph(
  actorId: string,
  actorName: string,
  techniques: string[],
  tools: string[],
  iocs: IoCSummary[],
): { nodes: OrbitalNode[]; links: OrbitalLink[] } {
  const nodes: OrbitalNode[] = [];
  const links: OrbitalLink[] = [];

  nodes.push({ id: actorId, label: actorName, type: 'actor', orbit: 0 });

  const shownTools = tools.slice(0, MAX_TOOLS);
  for (const t of shownTools) {
    const tid = `tool:${t}`;
    nodes.push({ id: tid, label: t, type: 'tool', orbit: 1 });
    links.push({ source: actorId, target: tid, strength: 0.6 });
  }

  const shownTtps = techniques.slice(0, MAX_TTPS);
  for (const ttp of shownTtps) {
    const tid = `ttp:${ttp}`;
    nodes.push({ id: tid, label: ttp, type: 'ttp', orbit: 2 });
    links.push({ source: actorId, target: tid, strength: 0.4 });
    if (shownTools.length > 0) {
      const toolIdx = Math.abs(ttp.charCodeAt(1) ?? 0) % shownTools.length;
      links.push({ source: `tool:${shownTools[toolIdx]}`, target: tid, strength: 0.2 });
    }
  }

  const shownIocs = iocs.slice(0, MAX_IOCS);
  for (const ioc of shownIocs) {
    const nid = `ioc:${ioc.id}`;
    const shortVal = ioc.value.length > 16 ? ioc.value.slice(0, 14) + '…' : ioc.value;
    nodes.push({ id: nid, label: shortVal, type: 'ioc', orbit: 3 });
    links.push({ source: actorId, target: nid, strength: 0.15 });
    if (shownTtps.length > 0) {
      const ttpIdx = Math.abs(ioc.value.charCodeAt(0) ?? 0) % shownTtps.length;
      links.push({ source: `ttp:${shownTtps[ttpIdx]}`, target: nid, strength: 0.1 });
    }
  }

  return { nodes, links };
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function CanvasOrbital({
  actorId,
  actorName,
  techniques,
  tools,
  iocs = [],
  densityLevel: densityProp = 2,
  width = 700,
  height = 600,
}: CanvasOrbitalProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const simRef = useRef<d3.Simulation<OrbitalNode, OrbitalLink> | null>(null);
  const nodesRef = useRef<OrbitalNode[]>([]);
  const linksRef = useRef<OrbitalLink[]>([]);
  const transformRef = useRef<d3.ZoomTransform>(d3.zoomIdentity);
  const hoveredRef = useRef<OrbitalNode | null>(null);
  const rafRef = useRef<number | null>(null);
  const [dims, setDims] = React.useState({ w: width, h: height });

  // ── Granular Zustand selectors (graph only re-renders for its own slices) ──
  const selectedNodeId = useActorDetailStore(s => s.selectedNodeId);
  const setSelectedNodeId = useActorDetailStore(s => s.setSelectedNodeId);
  const setHighlightedTechniques = useActorDetailStore(s => s.setHighlightedTechniques);

  // ── Refs for reactive values consumed inside stable draw() ────────────────
  // This breaks the stale-closure problem: draw's deps array is [],
  // yet it always reads the latest values via these refs.
  const selectedNodeIdRef = useRef<string | null>(selectedNodeId);
  const densityLevelRef = useRef<DensityLevel>(densityProp);
  const iocsRef = useRef<IoCSummary[]>(iocs);

  useEffect(() => { selectedNodeIdRef.current = selectedNodeId; }, [selectedNodeId]);
  useEffect(() => { densityLevelRef.current = densityProp; }, [densityProp]);
  useEffect(() => { iocsRef.current = iocs; }, [iocs]);

  const { nodes: initNodes, links: initLinks } = useMemo(
    () => buildGraph(actorId, actorName, techniques, tools, iocs),
    [actorId, actorName, techniques, tools, iocs],
  );

  // ── Stable draw — no closure over reactive state (reads via refs) ─────────

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const w = canvas.width;
    const h = canvas.height;
    const t = transformRef.current;
    const cx = w / 2;
    const cy = h / 2;
    const selectedId = selectedNodeIdRef.current;
    const density = densityLevelRef.current;
    const currentIocs = iocsRef.current;

    ctx.clearRect(0, 0, w, h);
    ctx.save();
    ctx.translate(t.x, t.y);
    ctx.scale(t.k, t.k);

    // Orbital rings
    for (const r of ORBIT_RADII) {
      if (r === 0) continue;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(255,255,255,0.05)';
      ctx.lineWidth = 1 / t.k;
      ctx.setLineDash([4 / t.k, 6 / t.k]);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Links
    for (const l of linksRef.current) {
      const src = l.source as OrbitalNode;
      const tgt = l.target as OrbitalNode;
      if (!src.x || !src.y || !tgt.x || !tgt.y) continue;
      const highlight = src.id === selectedId || tgt.id === selectedId;
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.strokeStyle = highlight ? `${TYPE_COLORS[src.type]}80` : 'rgba(255,255,255,0.06)';
      ctx.lineWidth = highlight ? 1.5 / t.k : 0.5 / t.k;
      ctx.stroke();
    }

    // Nodes
    for (const n of nodesRef.current) {
      if (!n.x || !n.y) continue;
      const r = TYPE_RADIUS[n.type];
      const iocDecayState = n.type === 'ioc'
        ? (currentIocs.find(i => `ioc:${i.id}` === n.id)?.decay_state ?? '')
        : '';
      const color = n.type === 'ioc'
        ? (DECAY_STATE_COLORS[iocDecayState] ?? TYPE_COLORS.ioc)
        : TYPE_COLORS[n.type];
      const isSelected = n.id === selectedId;
      const isHovered = hoveredRef.current?.id === n.id;

      if (isSelected || isHovered) {
        ctx.shadowColor = color;
        ctx.shadowBlur = 16 / t.k;
      }

      ctx.beginPath();
      ctx.arc(n.x, n.y, r + (isSelected ? 3 : 0), 0, Math.PI * 2);
      ctx.fillStyle = isSelected ? color : `${color}cc`;
      ctx.fill();

      if (isSelected || isHovered) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.5 / t.k;
        ctx.stroke();
      }
      ctx.shadowBlur = 0;

      const showLabel = density >= 2 || isSelected || isHovered || n.type === 'actor';
      if (showLabel || t.k > 0.8) {
        ctx.font = `${n.type === 'actor' ? 'bold ' : ''}${Math.max(8, 10 / t.k)}px "JetBrains Mono", monospace`;
        ctx.fillStyle = isSelected ? '#ffffff' : '#9ca3af';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillText(n.label, n.x, n.y + r + 3 / t.k);
      }

      if (density >= 2 || n.type === 'actor') {
        ctx.font = `${Math.max(6, (n.type === 'actor' ? 12 : 8) / t.k)}px sans-serif`;
        ctx.fillStyle = '#ffffff';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(TYPE_ICONS[n.type], n.x, n.y);
      }
    }

    ctx.restore();
  }, []); // stable — all reactive values read via refs

  // Re-draw when selectedNodeId or density changes (without recreating draw)
  useEffect(() => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    rafRef.current = requestAnimationFrame(draw);
  }, [selectedNodeId, densityProp, draw]);

  // ── Simulation ────────────────────────────────────────────────────────────

  useEffect(() => {
    const cw = containerRef.current?.clientWidth || width;
    const ch = containerRef.current?.clientHeight || height;
    const cx = cw / 2;
    const cy = ch / 2;

    nodesRef.current = initNodes.map(n => ({ ...n }));
    linksRef.current = initLinks.map(l => ({ ...l }));

    const actorNode = nodesRef.current.find(n => n.type === 'actor');
    if (actorNode) { actorNode.fx = cx; actorNode.fy = cy; }

    // Pre-position on orbital rings to minimise cold-start chaos
    for (const n of nodesRef.current) {
      if (n.type === 'actor') continue;
      const orbitR = ORBIT_RADII[n.orbit];
      const sameOrbit = nodesRef.current.filter(m => m.orbit === n.orbit);
      const idx = sameOrbit.indexOf(n);
      const angle = (2 * Math.PI * idx) / sameOrbit.length - Math.PI / 2;
      n.x = cx + orbitR * Math.cos(angle);
      n.y = cy + orbitR * Math.sin(angle);
    }

    const sim = d3.forceSimulation<OrbitalNode>(nodesRef.current)
      .force('link', d3.forceLink<OrbitalNode, OrbitalLink>(linksRef.current)
        .id(d => d.id)
        .distance(d => {
          const src = d.source as OrbitalNode;
          const tgt = d.target as OrbitalNode;
          return Math.abs(ORBIT_RADII[src.orbit] - ORBIT_RADII[tgt.orbit]) + 60;
        })
        .strength(d => (d as OrbitalLink).strength),
      )
      .force('radial', (() => {
        return (alpha: number) => {
          for (const n of nodesRef.current) {
            if (n.type === 'actor') continue;
            const targetR = ORBIT_RADII[n.orbit];
            const dx = (n.x ?? cx) - cx;
            const dy = (n.y ?? cy) - cy;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = (dist - targetR) * alpha * 0.6;
            n.vx = (n.vx ?? 0) - (dx / dist) * force;
            n.vy = (n.vy ?? 0) - (dy / dist) * force;
          }
        };
      })())
      .force('collide', d3.forceCollide<OrbitalNode>(n => TYPE_RADIUS[n.type] + 4).strength(0.8))
      .force('center', d3.forceCenter(cx, cy).strength(0.05))
      .alphaDecay(0.02)
      .on('tick', () => {
        // draw is stable — never a stale reference
        if (rafRef.current) cancelAnimationFrame(rafRef.current);
        rafRef.current = requestAnimationFrame(draw);
      });

    simRef.current = sim;

    return () => {
      // Always stop simulation on cleanup to prevent CPU saturation
      sim.stop();
      simRef.current = null;
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [initNodes, initLinks, draw, width, height]);

  // ── Zoom & interaction ────────────────────────────────────────────────────

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const zoom = d3.zoom<HTMLCanvasElement, unknown>()
      .scaleExtent([0.3, 4])
      .on('zoom', e => {
        transformRef.current = e.transform;
        if (rafRef.current) cancelAnimationFrame(rafRef.current);
        rafRef.current = requestAnimationFrame(draw);
      });

    d3.select(canvas).call(zoom);

    const getNode = (e: MouseEvent): OrbitalNode | null => {
      const rect = canvas.getBoundingClientRect();
      const t = transformRef.current;
      const mx = (e.clientX - rect.left - t.x) / t.k;
      const my = (e.clientY - rect.top - t.y) / t.k;
      let closest: OrbitalNode | null = null;
      let minDist = 24;
      for (const n of nodesRef.current) {
        if (!n.x || !n.y) continue;
        const d = Math.hypot(n.x - mx, n.y - my);
        if (d < TYPE_RADIUS[n.type] + 4 && d < minDist) { closest = n; minDist = d; }
      }
      return closest;
    };

    const onMove = (e: MouseEvent) => {
      const n = getNode(e);
      if (hoveredRef.current?.id !== n?.id) {
        hoveredRef.current = n;
        canvas.style.cursor = n ? 'pointer' : 'grab';
        if (rafRef.current) cancelAnimationFrame(rafRef.current);
        rafRef.current = requestAnimationFrame(draw);
      }
    };

    const onClick = (e: MouseEvent) => {
      const n = getNode(e);
      if (!n) { setSelectedNodeId(null); setHighlightedTechniques([]); return; }
      setSelectedNodeId(n.id);
      if (n.type === 'ttp') {
        setHighlightedTechniques([n.label]);
      } else if (n.type !== 'actor') {
        const linkedTtps = linksRef.current
          .flatMap(l => {
            const src = l.source as OrbitalNode;
            const tgt = l.target as OrbitalNode;
            if (src.id === n.id || tgt.id === n.id) return [src, tgt];
            return [];
          })
          .filter(m => m.type === 'ttp')
          .map(m => m.label);
        setHighlightedTechniques(linkedTtps);
      } else {
        setHighlightedTechniques([]);
      }
    };

    const onLeave = () => {
      hoveredRef.current = null;
      canvas.style.cursor = 'grab';
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      rafRef.current = requestAnimationFrame(draw);
    };

    canvas.addEventListener('mousemove', onMove);
    canvas.addEventListener('click', onClick);
    canvas.addEventListener('mouseleave', onLeave);
    return () => {
      d3.select(canvas).on('.zoom', null);
      canvas.removeEventListener('mousemove', onMove);
      canvas.removeEventListener('click', onClick);
      canvas.removeEventListener('mouseleave', onLeave);
    };
  }, [draw, setSelectedNodeId, setHighlightedTechniques]);

  // ── ResizeObserver ────────────────────────────────────────────────────────

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new ResizeObserver(entries => {
      const { width: w, height: h } = entries[0].contentRect;
      if (canvasRef.current) {
        canvasRef.current.width = w;
        canvasRef.current.height = h;
        setDims({ w, h });
      }
      draw();
    });
    obs.observe(el);
    // Initial size
    const rect = el.getBoundingClientRect();
    if (canvasRef.current && rect.width > 0) {
      canvasRef.current.width = rect.width;
      canvasRef.current.height = rect.height || height;
      setDims({ w: rect.width, h: rect.height || height });
    }
    return () => obs.disconnect();
  }, [draw, height]);

  // ─── Legend ───────────────────────────────────────────────────────────────

  const nodeCounts = {
    tools: initNodes.filter(n => n.type === 'tool').length,
    ttps:  initNodes.filter(n => n.type === 'ttp').length,
    iocs:  initNodes.filter(n => n.type === 'ioc').length,
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-4 flex-wrap px-1">
        {(Object.entries(TYPE_COLORS) as [OrbitalNode['type'], string][])
          .filter(([t]) => t !== 'actor')
          .map(([type, color]) => (
            <div key={type} className="flex items-center gap-1.5 text-[9px] font-mono text-gray-400">
              <span style={{ color }}>{TYPE_ICONS[type]}</span>
              <span style={{ color }}>{type.toUpperCase()}</span>
              <span className="text-gray-600">
                ({type === 'tool' ? nodeCounts.tools : type === 'ttp' ? nodeCounts.ttps : nodeCounts.iocs})
              </span>
            </div>
          ))
        }
        <span className="ml-auto text-[9px] font-mono text-gray-600">
          {initNodes.length - 1} nœuds · cliquer pour filtrer
        </span>
      </div>

      <div
        ref={containerRef}
        style={{ width: '100%', height: dims.h, minHeight: 480, position: 'relative' }}
        className="rounded-lg overflow-hidden bg-[#020508]"
      >
        <canvas
          ref={canvasRef}
          width={dims.w}
          height={dims.h}
          style={{ display: 'block', cursor: 'grab' }}
          aria-label={`Graphe orbital — ${actorName}`}
        />

        {selectedNodeId && (
          <button
            onClick={() => { setSelectedNodeId(null); setHighlightedTechniques([]); }}
            className="absolute top-2 right-2 text-[9px] font-mono px-2 py-1 rounded border border-gray-700 bg-[#0a0f1a] text-gray-400 hover:text-white hover:border-gray-500 transition-colors"
          >
            ✕ Désélectionner
          </button>
        )}

        <div className="absolute bottom-2 left-2 flex flex-col gap-0.5 pointer-events-none">
          {(['Orbit 1 — Outils', 'Orbit 2 — TTPs', 'Orbit 3 — IoCs'] as const).map((label, i) => (
            <span key={i} className="text-[8px] font-mono text-gray-700">{label}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
