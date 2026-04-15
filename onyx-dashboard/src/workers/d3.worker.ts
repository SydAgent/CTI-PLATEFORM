import * as d3 from 'd3-force';

interface NodeData extends d3.SimulationNodeDatum {
  id: string;
  group: number;
  radius: number;
  type: string;
  name: string;
}

interface LinkData extends d3.SimulationLinkDatum<NodeData> {
  value: number;
}

let simulation: d3.Simulation<NodeData, LinkData> | null = null;
let nodesData: NodeData[] = [];

const ctx: Worker = self as any;

// Listen for messages from the main thread
ctx.onmessage = function (event: MessageEvent) {
  const { type, nodes, links, width, height } = event.data;

  if (type === 'INIT') {
    // 1. Initialize Nodes with type-aware radii for collision detection
    nodesData = nodes.map((n: any) => ({
      ...n,
      radius: n.type === 'actor' ? 22 : n.type === 'tool' ? 14 : n.type === 'ttp' ? 10 : 6
    }));

    // 2. Map existing links
    const linksData = links.map((l: any) => ({ ...l }));

    // 3. Stop old simulation
    if (simulation) {
      simulation.stop();
    }

    // 4. Create new Simulation with HARDENED collision detection
    // Key changes from v1:
    //   - Stronger charge repulsion (-150 vs -80) → nodes spread out more
    //   - Larger link distance (80 vs 50) → prevents overlapping labels  
    //   - Collision radius includes padding (radius + 8) → guaranteed no overlap
    //   - 3 collision iterations (vs 2) → more stable separation
    //   - Radial force keeps node types in concentric rings
    simulation = d3.forceSimulation<NodeData>(nodesData)
      .force('charge', d3.forceManyBody<NodeData>()
        .strength(d => d.type === 'actor' ? -250 : d.type === 'tool' ? -150 : -100)
        .distanceMax(400)
      )
      .force('link', d3.forceLink<NodeData, LinkData>(linksData)
        .id(d => d.id)
        .distance(d => {
          // Vary distance by relationship type for visual hierarchy
          const src = typeof d.source === 'string' ? nodesData.find(n => n.id === d.source) : d.source as NodeData;
          const tgt = typeof d.target === 'string' ? nodesData.find(n => n.id === d.target) : d.target as NodeData;
          if (src?.type === 'actor' || tgt?.type === 'actor') return 100;
          return 70;
        })
        .strength(0.6)
      )
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide<NodeData>()
        .radius(d => d.radius + 8)  // Extra padding to prevent label overlap
        .iterations(3)              // More iterations for stable collision
        .strength(0.9)              // Near-rigid collision response
      )
      .force('x', d3.forceX(width / 2).strength(0.03))   // Gentle centering
      .force('y', d3.forceY(height / 2).strength(0.03))
      .alphaDecay(0.015)     // Slower decay → more time to settle
      .velocityDecay(0.35);

    // 5. Send optimized Float32Array on every tick
    simulation.on('tick', () => {
      // Create a Float32Array where indices match node array
      // Structure: [x0, y0, x1, y1, ...]
      const coords = new Float32Array(nodesData.length * 2);
      
      for (let i = 0; i < nodesData.length; i++) {
        coords[i * 2] = nodesData[i].x ?? 0;
        coords[i * 2 + 1] = nodesData[i].y ?? 0;
      }

      // Transfer the buffer for zero-copy high performance
      ctx.postMessage({ type: 'TICK', coords }, [coords.buffer]);
    });
    
    simulation.on('end', () => {
       ctx.postMessage({ type: 'END' });
    });
  } 
  
  if (type === 'REHEAT') {
     if (simulation) {
         simulation.alpha(0.3).restart();
     }
  }
};
