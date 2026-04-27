"use client";
import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import { useOmegaStore, GraphNode, GraphEdge } from '../../lib/store/omegaStore';

const SHAPES: Record<GraphNode['type'], (g: any, s: number) => void> = {
  actor:   (g, s) => g.append('polygon').attr('points', `0,${-s} ${s*0.866},${s*0.5} ${-s*0.866},${s*0.5}`).attr('fill', '#f43f5e').attr('stroke', '#fda4af').attr('stroke-width', 2),
  ip:      (g, s) => g.append('rect').attr('x', -s*0.8).attr('y', -s*0.8).attr('width', s*1.6).attr('height', s*1.6).attr('rx', 2).attr('fill', '#3b82f6').attr('stroke', '#93c5fd').attr('stroke-width', 2),
  malware: (g, s) => g.append('polygon').attr('points', Array.from({length:6}, (_,i)=>{const a=(Math.PI/3)*i; return `${Math.cos(a)*s},${Math.sin(a)*s}`;}).join(' ')).attr('fill', '#a855f7').attr('stroke', '#d8b4fe').attr('stroke-width', 2),
  ttp:     (g, s) => g.append('circle').attr('r', s*0.9).attr('fill', '#f97316').attr('stroke', '#fdba74').attr('stroke-width', 2),
};

const NODE_COLORS: Record<GraphNode['type'], string> = { actor: '#f43f5e', ip: '#3b82f6', malware: '#a855f7', ttp: '#f97316' };

function ActionPanel({ node, onClose }: { node: GraphNode; onClose: () => void }) {
  const cmds: Record<GraphNode['type'], string> = {
    actor: 'Deploy Zero Trust Perimeter Block',
    ip: `iptables -A INPUT -s ${node.label} -j DROP`,
    malware: 'Push YARA rule to EDR fleet',
    ttp: 'Update SIGMA rule detection threshold'
  };

  return (
    <div className="absolute top-6 right-6 w-80 bg-[#070b14]/95 backdrop-blur-xl border border-slate-700 rounded-xl shadow-[0_0_40px_rgba(0,0,0,0.8)] z-30 flex flex-col overflow-hidden animate-in slide-in-from-right-8 duration-300">
      <div className="px-5 py-3 border-b border-slate-800 flex justify-between items-center bg-black/40">
        <span className="text-[10px] uppercase tracking-widest font-mono text-slate-400 font-bold flex items-center gap-2">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS[node.type] }} />
          {node.type} INTERACTION
        </span>
        <button onClick={onClose} className="text-slate-500 hover:text-white font-bold">✕</button>
      </div>
      <div className="p-5 flex flex-col gap-4">
        <div>
           <p className="text-xl font-black font-mono text-white tracking-tight break-all">{node.label}</p>
           {node.severity && <p className="text-[10px] font-mono text-rose-400 mt-1 uppercase border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 rounded inline-block">SEV: {node.severity}</p>}
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded p-3">
          <p className="text-[9px] font-mono text-slate-500 uppercase mb-2 font-bold">Mitigation Command (Auto-signed)</p>
          <code className="text-[10px] font-mono text-emerald-400 break-all">{cmds[node.type]}</code>
        </div>
        <button className="w-full py-3 bg-white text-black text-[10px] font-black uppercase tracking-[0.2em] rounded hover:bg-slate-200 transition-colors">
          Execute Policy Push
        </button>
      </div>
    </div>
  );
}

export default function ThreatGraph2D() {
  const { graphNodes, graphEdges } = useOmegaStore();
  const svgRef = useRef<SVGSVGElement>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const buildGraph = useCallback(() => {
    if (!svgRef.current || graphNodes.length === 0) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    
    const W = svgRef.current.clientWidth || 800;
    const H = svgRef.current.clientHeight || 600;

    const nodeData = graphNodes.map(n => ({ ...n } as any));
    const linkData = graphEdges.map(e => ({ ...e } as any));

    const g = svg.append('g');
    svg.call(d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.2, 5]).on('zoom', ({ transform }) => g.attr('transform', transform)));

    g.append('defs').append('marker').attr('id', 'arrow').attr('viewBox', '0 -4 8 8').attr('refX', 22).attr('refY', 0)
     .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto').append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', '#475569');

    const link = g.append('g').selectAll('line').data(linkData).enter().append('line')
      .attr('stroke', '#334155').attr('stroke-width', 1).attr('marker-end', 'url(#arrow)');

    const nodeG = g.append('g').selectAll('g').data(nodeData).enter().append('g')
      .attr('cursor', 'crosshair').on('click', (_, d: any) => setSelectedNode(d as GraphNode))
      .call(d3.drag<SVGGElement, any>()
        .on('start', (event, d) => { if (!event.active) sim.alphaTarget(0.1).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on('end', (event, d) => { if (!event.active) sim.alphaTarget(0); d.fx = d.x; d.fy = d.y; }));

    nodeG.each(function(d: any) { SHAPES[d.type as GraphNode['type']]?.(d3.select(this), 14); });

    nodeG.append('text').attr('y', 26).attr('text-anchor', 'middle').attr('font-size', 10).attr('font-family', 'monospace')
      .attr('fill', '#cbd5e1').attr('font-weight', 'bold').text((d: any) => d.label);

    const sim = d3.forceSimulation(nodeData)
      .force('link', d3.forceLink(linkData).id((d: any) => d.id).distance(150))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(W/2, H/2))
      .force('collide', d3.forceCollide().radius(40))
      .alphaDecay(0.08); // High dampening for extreme stability

    sim.on('tick', () => {
      link.attr('x1', (d: any) => d.source.x).attr('y1', (d: any) => d.source.y).attr('x2', (d: any) => d.target.x).attr('y2', (d: any) => d.target.y);
      nodeG.attr('transform', (d: any) => `translate(${d.x},${d.y})`);
    });
    
    // Auto-pin after quick stabilization
    setTimeout(() => { sim.alphaTarget(0); nodeData.forEach((d:any) => { d.fx = d.x; d.fy = d.y; }); }, 2000);

  }, [graphNodes, graphEdges]);

  useEffect(() => { buildGraph(); }, [buildGraph]);

  return (
    <div className="relative bg-[#02040a] border border-slate-800 rounded-xl overflow-hidden shadow-2xl h-[600px] font-sans">
      <div className="absolute top-6 left-6 z-20 pointer-events-none">
         <h2 className="text-xl font-black text-white uppercase tracking-[0.2em] font-mono drop-shadow-md">Threat Topology Graph</h2>
         <p className="text-[10px] font-mono text-slate-400 mt-1">{graphNodes.length} Nodes · {graphEdges.length} Edges</p>
      </div>

      {graphNodes.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-full gap-4 opacity-40">
           <div className="text-5xl filter grayscale">🕸</div>
           <p className="text-xs font-mono uppercase tracking-widest text-slate-500">Awaiting Topology Data</p>
        </div>
      ) : <svg ref={svgRef} width="100%" height="100%" className="block outline-none" />}

      {selectedNode && <ActionPanel node={selectedNode} onClose={() => setSelectedNode(null)} />}
      
      <div className="absolute bottom-6 left-6 z-20 bg-black/60 border border-slate-800 backdrop-blur rounded p-3 flex gap-4 pointer-events-none">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <div key={type} className="flex items-center gap-2 text-[9px] font-mono text-slate-300 font-bold uppercase tracking-wider">
             <div className="w-2 h-2 rounded-sm" style={{ backgroundColor: color }} /> {type}
          </div>
        ))}
      </div>
    </div>
  );
}
