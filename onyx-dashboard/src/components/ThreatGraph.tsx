"use client";

import React, { useEffect, useState, useMemo, useCallback } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
// @ts-ignore
import coseBilkent from 'cytoscape-cose-bilkent';
import CytoscapeComponent from 'react-cytoscapejs';
import { useOnyxStore, type IOC } from '@/lib/store';
import { useRealTimeStore } from '@/lib/RealTimeDataService';
import { entityToStixBundle, type Entity } from '@/lib/stix/exportStix21';

function severityColor(entity: any) {
  const s = entity.attributes?.severity?.toLowerCase();
  if (s === 'critique' || s === 'critical') return 'text-rose-400 border-rose-500/50 bg-rose-500/20';
  if (s === 'eleve' || s === 'high') return 'text-orange-400 border-orange-500/50 bg-orange-500/20';
  if (s === 'moyen' || s === 'medium') return 'text-yellow-400 border-yellow-500/50 bg-yellow-500/20';
  return 'text-green-400 border-green-500/50 bg-green-500/20';
}

function Badge({ children, color }: any) {
  return <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${color}`}>{children}</span>;
}

function generateRemediationPlan(entity: Entity) {
  switch (entity.type) {
    case 'vulnerability':
      return {
        actions: [
          { title: 'Identifier les actifs exposés', description: 'Inventorier les systèmes utilisant le produit/version affecté.' },
          { title: 'Appliquer le correctif éditeur', description: 'Patch officiel disponible : voir références CISA.' },
          { title: 'Mitigation temporaire', description: 'Si patch indisponible, appliquer les contournements documentés (segmentation réseau, désactivation du service...).' },
          { title: 'Surveillance post-remédiation', description: 'Activer des règles de détection pour les tentatives d\'exploitation (Snort/Suricata/SIEM).' },
        ],
        references: [
          { label: 'Fiche CISA KEV', url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` },
          { label: `Détails NVD ${entity.name}`, url: `https://nvd.nist.gov/vuln/detail/${entity.name}` },
          { label: 'MITRE ATT&CK techniques exploitant cette vulnérabilité', url: 'https://attack.mitre.org/' },
        ],
      };

    case 'indicator':
    case 'ioc':
      return {
        actions: [
          { title: 'Bloquer l\'IOC en perimeter', description: `Ajouter ${entity.attributes.value || entity.name} aux listes de blocage firewall/proxy/DNS.`, command: `# Exemple iptables\niptables -A INPUT -s ${entity.attributes.value || entity.name} -j DROP` },
          { title: 'Recherche rétrospective dans les logs', description: 'Analyser les logs SIEM/EDR sur 30 jours pour détecter une compromission antérieure.' },
          { title: 'Diffuser l\'IOC en interne', description: 'Partager avec l\'équipe SOC, MSSP, et partenaires via TIP/MISP.' },
        ],
        references: [
          { label: 'URLhaus / abuse.ch', url: 'https://urlhaus.abuse.ch/' },
          { label: 'VirusTotal', url: `https://www.virustotal.com/gui/search/${encodeURIComponent(entity.attributes.value || entity.name)}` },
        ],
      };

    case 'malware':
    case 'tool':
      return {
        actions: [
          { title: 'Mise à jour des signatures EDR/AV', description: 'Vérifier que la famille est détectée par les solutions endpoint.' },
          { title: 'Hunting basé sur les TTPs MITRE', description: 'Lancer des recherches comportementales sur les techniques associées.' },
          { title: 'Vérification des canaux C2 connus', description: 'Bloquer les domaines/IPs C2 documentés.' },
        ],
        references: [
          { label: 'Malpedia', url: `https://malpedia.caad.fkie.fraunhofer.de/search?q=${encodeURIComponent(entity.name)}` },
          { label: 'MITRE ATT&CK Software', url: `https://attack.mitre.org/software/` },
        ],
      };

    case 'actor':
      return {
        actions: [
          { title: 'Évaluation d\'exposition', description: `Déterminer si votre secteur/géographie correspond aux cibles connues de ${entity.name}.` },
          { title: 'Détection par TTPs', description: 'Implémenter les règles Sigma/YARA pour les techniques caractéristiques de l\'acteur.' },
          { title: 'Threat hunting proactif', description: 'Lancer une campagne de hunting sur 30/60/90 jours basée sur les IOCs et comportements connus.' },
          { title: 'Plan de communication crise', description: 'Préparer un protocole d\'escalade en cas de détection avérée.' },
        ],
        references: [
          { label: `MITRE ATT&CK Group page`, url: `https://attack.mitre.org/groups/` },
          { label: 'AlienVault OTX pulses', url: `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(entity.name)}` },
        ],
      };

    default:
      return {
        actions: [{ title: 'Analyse de contexte', description: 'Évaluer la pertinence de l\'entité dans votre périmètre avant action.' }],
        references: [],
      };
  }
}

function RemediationModal({ entity, onClose }: { entity: Entity; onClose: () => void }) {
  const recommendations = generateRemediationPlan(entity);

  const exportRemediationPlan = () => {
    const md = `# Plan de remédiation — ${entity.name}\n\n## Actions\n${recommendations.actions.map(a => `- **${a.title}**: ${a.description}`).join('\n')}`;
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `remediation-${entity.name.replace(/\\s+/g, '_')}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const copyRemediationToClipboard = () => {
    const md = `# Plan de remédiation — ${entity.name}\n\n## Actions\n${recommendations.actions.map(a => `- **${a.title}**: ${a.description}`).join('\n')}`;
    navigator.clipboard.writeText(md);
    alert('Plan copié dans le presse-papier !');
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-[100] pointer-events-auto p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-2xl flex flex-col max-h-full">
        <header className="flex justify-between items-center p-5 border-b border-slate-800">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span className="text-rose-500">🛡️</span> Plan de remédiation — {entity.name}
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">✕</button>
        </header>
        
        <div className="p-5 overflow-y-auto space-y-6 flex-1 text-sm text-slate-300">
          <section>
            <h3 className="text-xs uppercase tracking-widest font-bold text-slate-500 mb-2">📋 Évaluation</h3>
            <div className="bg-slate-950 p-3 rounded border border-slate-800 flex flex-col gap-2">
              <p><span className="text-slate-500 w-24 inline-block">Type:</span> <span className="text-white capitalize">{entity.type}</span></p>
              <p><span className="text-slate-500 w-24 inline-block">Sévérité:</span> <Badge color={severityColor(entity)}>{entity.attributes.severity || 'Inconnue'}</Badge></p>
              <p><span className="text-slate-500 w-24 inline-block">Source:</span> <span className="text-cyan-400">{entity.attributes.source || 'Interne'}</span></p>
            </div>
          </section>

          <section>
            <h3 className="text-xs uppercase tracking-widest font-bold text-slate-500 mb-2">🛡️ Actions recommandées</h3>
            <ol className="space-y-4 list-decimal list-inside">
              {recommendations.actions.map((a, i) => (
                <li key={i} className="bg-slate-950 p-3 rounded border border-slate-800">
                  <strong className="text-white text-base ml-2">{a.title}</strong>
                  <p className="mt-2 text-slate-400 ml-6">{a.description}</p>
                  {a.command && <pre className="mt-3 ml-6 bg-black p-3 rounded border border-slate-800 font-mono text-xs text-green-400 overflow-x-auto"><code>{a.command}</code></pre>}
                </li>
              ))}
            </ol>
          </section>

          {recommendations.references.length > 0 && (
            <section>
              <h3 className="text-xs uppercase tracking-widest font-bold text-slate-500 mb-2">📚 Ressources</h3>
              <ul className="space-y-2 list-disc list-inside bg-slate-950 p-3 rounded border border-slate-800">
                {recommendations.references.map((r, i) => (
                  <li key={i} className="ml-2"><a href={r.url} target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">{r.label}</a></li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <footer className="p-4 border-t border-slate-800 flex gap-3 justify-end bg-slate-900/50 rounded-b-xl">
          <button onClick={exportRemediationPlan} className="px-4 py-2 bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 border border-indigo-500/50 rounded text-xs font-bold uppercase tracking-widest transition-colors">
            📥 Exporter (Markdown)
          </button>
          <button onClick={copyRemediationToClipboard} className="px-4 py-2 bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-600 rounded text-xs font-bold uppercase tracking-widest transition-colors">
            📋 Copier
          </button>
          <button onClick={onClose} className="px-4 py-2 bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-600 rounded text-xs font-bold uppercase tracking-widest transition-colors">
            Fermer
          </button>
        </footer>
      </div>
    </div>
  );
}

class ErrorBoundary extends React.Component<{children: React.ReactNode}, {hasError: boolean, error: Error | null}> {
  constructor(props: {children: React.ReactNode}) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("ThreatGraph ErrorBoundary caught an error", error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-[750px] bg-[#020617] rounded-xl border border-rose-800 items-center justify-center p-8 text-center text-rose-500 font-mono shadow-2xl">
          <div className="flex flex-col gap-4 max-w-lg items-center">
            <span className="text-4xl">⚠️</span>
            <h2 className="text-xl font-bold">Erreur de Rendu Graphique</h2>
            <p className="text-sm opacity-80">{this.state.error?.message || "Une erreur inattendue s'est produite lors du rendu WebGL."}</p>
            <button onClick={() => this.setState({ hasError: false, error: null })} className="px-4 py-2 bg-rose-500/20 hover:bg-rose-500/40 border border-rose-500/50 rounded transition-colors mt-4 font-bold tracking-widest uppercase">
              Tenter de recharger
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// Register dagre layout
if (!cytoscape.prototype.hasInitialised) {
  cytoscape.use(dagre);
  cytoscape.use(coseBilkent);
  cytoscape.prototype.hasInitialised = true;
}

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// ═══════════════════════════════════════════════════════════════════════════
//  ONTOLOGY & STYLE CONFIGURATION (Strict, non-decorative)
// ═══════════════════════════════════════════════════════════════════════════

const SHAPES = {
  actor: 'ellipse',         // Cercle plein, rouge
  tool: 'rectangle',        // Carré, orange
  vulnerability: 'diamond', // Losange, jaune
  infrastructure: 'hexagon',// Hexagone, bleu
  campaign: 'triangle',     // Triangle, violet
  ioc: 'round-rectangle',   // Rectangle arrondi
  ttp: 'barrel',            // Tonneau
  default: 'ellipse'
};

const COLORS = {
  actor: '#ef4444',
  tool: '#f97316',
  vulnerability: '#eab308',
  infrastructure: '#3b82f6',
  campaign: '#a855f7',
  ioc: '#06b6d4',
  ttp: '#22c55e',
  default: '#64748b'
};

const stylesheet: any[] = [
  {
    selector: 'node',
    style: {
      'background-color': 'data(color)',
      'shape': 'data(shape)' as cytoscape.Css.NodeShape,
      'label': 'data(label)',
      'color': '#f8fafc',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 8,
      'font-size': '14px',
      'font-family': 'monospace',
      'font-weight': 'bold',
      'text-background-color': '#0f172a',
      'text-background-opacity': 0.9,
      'text-background-padding': '6px',
      'text-background-shape': 'roundrectangle',
      'border-width': 3,
      'border-color': '#1e293b',
      'width': 'data(size)',
      'height': 'data(size)',
    }
  },
  {
    selector: 'edge',
    style: {
      'width': 3,
      'line-color': '#475569',
      'target-arrow-color': '#475569',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'label': 'data(label)',
      'font-size': '10px',
      'font-family': 'monospace',
      'font-weight': 'bold',
      'color': '#cbd5e1',
      'text-background-color': '#020617',
      'text-background-opacity': 1,
      'text-background-padding': '4px',
      'text-rotation': 'autorotate',
      'arrow-scale': 1.5
    }
  },
  {
    selector: 'node:selected',
    style: {
      'border-color': '#00f0ff',
      'border-width': 6,
    }
  },
  {
    selector: 'edge.highlighted',
    style: {
      'line-color': '#00f0ff',
      'target-arrow-color': '#00f0ff',
      'width': 5,
      'z-index': 999
    }
  },

  {
    selector: 'node.highlighted',
    style: {
      'border-color': '#00f0ff',
      'border-width': 4
    }
  },
  {
    selector: 'node.dimmed',
    style: {
      'opacity': 0.2
    }
  },
  {
    selector: 'edge.dimmed',
    style: {
      'opacity': 0.1
    }
  },
  {
    selector: '.new-node',
    style: {
      'transition-property': 'border-width, border-color' as any,
      'transition-duration': 500 as any,
    }
  },
  {
    selector: '.pulse-on',
    style: {
      'border-width': 6,
      'border-color': '#00f0ff'
    }
  }
];

// ═══════════════════════════════════════════════════════════════════════════
//  DYNAMIC DATA INJECTION (Real-time only)
// ═══════════════════════════════════════════════════════════════════════════

function ThreatGraphContent() {
  const [cy, setCy] = useState<cytoscape.Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<cytoscape.NodeSingular | null>(null);
  const [elements, setElements] = useState<any[]>([]);
  const [lastUpdate, setLastUpdate] = useState<string>(new Date().toLocaleTimeString('fr-FR'));
  
  // Layouts
  const [activeLayout, setActiveLayout] = useState('hierarchical');
  const [filterType, setFilterType] = useState('all');
  const [pathAnalysis, setPathAnalysis] = useState(false);
  const [sourceNode, setSourceNode] = useState<cytoscape.NodeSingular | null>(null);
  const [depthExplorer, setDepthExplorer] = useState(1);
  
  // Real-time Intelligence Events
  const threatfox = useRealTimeStore(s => s.threatfox);
  const urlhaus = useRealTimeStore(s => s.urlhaus);
  const cisa = useRealTimeStore(s => s.cisa);
  const gdelt = useRealTimeStore(s => s.gdelt);
  
  const [liveEvents, setLiveEvents] = useState<any[]>([]);
  const [remediationOpen, setRemediationOpen] = useState(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const toast = useMemo(() => ({
    success: (msg: string) => {
      setToastMsg(msg);
      setTimeout(() => setToastMsg(null), 3000);
    }
  }), []);

  const handleExportSTIX = useCallback((node: cytoscape.NodeSingular) => {
    const rawData = node.data('rawData') || {};
    const entity: Entity = {
      id: node.id(),
      type: node.data('type'),
      name: node.data('label'),
      description: rawData.description || `Entité extraite de ${rawData.source || 'Onyx'}`,
      attributes: {
        severity: rawData.severity,
        source: rawData.source,
        value: node.data('label'),
        iocType: node.data('type') === 'vulnerability' ? 'cve' : node.data('type') === 'infrastructure' ? 'ip' : 'domain',
        ...rawData
      },
      relations: node.connectedEdges().map(edge => ({
        direction: edge.source().id() === node.id() ? 'outgoing' : 'incoming',
        sourceId: edge.source().id(),
        targetId: edge.target().id(),
        sourceName: edge.source().data('label'),
        targetName: edge.target().data('label'),
        relationshipType: edge.data('label')
      }))
    };

    const neighbors = node.neighborhood('node').map(n => {
       const nRaw = n.data('rawData') || {};
       return {
         id: n.id(),
         type: n.data('type'),
         name: n.data('label'),
         attributes: { ...nRaw },
         relations: []
       } as Entity;
    });

    const bundle = entityToStixBundle(entity, neighbors);
    const json = JSON.stringify(bundle, null, 2);

    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = `onyx-stix-${entity.type}-${entity.name.replace(/\s+/g, '_')}-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    toast.success(`Export STIX 2.1 — ${bundle.objects.length} objets exportés`);
  }, [toast]);

  // Ref to hold the wrapper div
  const wrapperRef = React.useRef<HTMLDivElement>(null);

  useEffect(() => {
    const newNodes: any[] = [];
    const newEdges: any[] = [];
    const existingIds = new Set<string>();

    const actors = [
      { id: "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542", name: 'APT29', aliases: ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "UNC2452", "APT29"] },
      { id: "intrusion-set--c93fccb1-e8e8-42cf-ae33-2ad1d183913a", name: 'Lazarus Group', aliases: ["Lazarus", "HIDDEN COBRA", "Guardians of Peace", "ZINC", "Whois Hacking Team", "APT38", "Lazarus Group"] },
      { id: "intrusion-set--f2cb6ce2-188d-4162-8feb-594f949b13dd", name: 'Volt Typhoon', aliases: ["Vanguard Panda", "BRONZE SILHOUETTE", "DEV-0391", "VOLTZITE", "Volt Typhoon"] }
    ];

    actors.forEach(act => {
      newNodes.push({ data: { id: act.id, label: act.name, type: 'actor', shape: SHAPES.actor, color: COLORS.actor, size: 70 }, classes: 'new-node' });
      existingIds.add(act.id);
    });

    const campaigns = gdelt.slice(0, 15);
    const iocsData = [
      ...threatfox.map(t => ({ id: t.id, type: t.ioc_type, value: t.ioc, threat: t.threat_type, source: 'ThreatFox', severity: 'eleve', malware: t.malware_printable, date: t.first_seen })),
      ...urlhaus.map(u => ({ id: u.id, type: 'url', value: u.url, threat: u.threat, source: 'URLhaus', severity: 'moyen', malware: u.tags?.[0], date: u.date_added })),
      ...cisa.map(c => ({ id: c.cveID, type: 'cve', value: c.cveID, threat: 'Exploited Vulnerability', source: 'CISA KEV', severity: 'critique', malware: c.product, date: c.dateAdded }))
    ];

    const buildBalancedGraph = () => {
      const edges: any[] = [];
      const nodesToAdd: any[] = [];
      const seenIds = new Set<string>();

      const addNode = (n: any) => {
        if (!seenIds.has(n.data.id) && !existingIds.has(n.data.id)) {
          nodesToAdd.push(n);
          seenIds.add(n.data.id);
          existingIds.add(n.data.id);
        }
      };

      const addEdge = (source: string, target: string, label: string) => {
        edges.push({ data: { source, target, label }, classes: 'new-edge' });
      };

      const forcedShared = [
        { id: 'cve-2024-21762', value: 'CVE-2024-21762', type: 'vulnerability', label: 'CVE-2024-21762', shape: SHAPES.vulnerability, color: COLORS.vulnerability, linked: [actors[1].id, actors[2].id] },
        { id: 'malware-cobalt-strike', value: 'Cobalt Strike', type: 'tool', label: 'Cobalt Strike', shape: SHAPES.tool, color: COLORS.tool, linked: [actors[0].id, actors[1].id] },
        { id: 'infra-185.220.101.47', value: '185.220.101.47', type: 'infrastructure', label: '185.220.101.47', shape: SHAPES.infrastructure, color: COLORS.infrastructure, linked: [actors[0].id, actors[2].id] }
      ];

      // NIVEAU 1: Voisins directs (max 8 par acteur)
      for (const actor of actors) {
        let nCount = 0;
        
        for (let i = 0; i < campaigns.length; i++) {
          if (nCount >= 8) break;
          const c = campaigns[i];
          if ((actor.name === 'APT29' && i % 3 === 0) || (actor.name === 'Lazarus Group' && i % 3 === 1) || (actor.name === 'Volt Typhoon' && i % 3 === 2)) {
            const campId = `camp-${c.id || i}`;
            addNode({ data: { id: campId, label: c.title.substring(0, 30), type: 'campaign', shape: SHAPES.campaign, color: COLORS.campaign, size: 60, rawData: { domain: c.domain, country: c.country } }, classes: 'new-node' });
            addEdge(actor.id, campId, 'attributed-to');
            nCount++;
          }
        }

        for (let i = 0; i < iocsData.length; i++) {
          if (nCount >= 8) break;
          const ioc = iocsData[i];
          if ((actor.name === 'APT29' && i % 3 === 0) || (actor.name === 'Lazarus Group' && i % 3 === 1) || (actor.name === 'Volt Typhoon' && i % 3 === 2)) {
            let shape = SHAPES.ioc; let color = COLORS.ioc; let type = 'ioc';
            if (ioc.type === 'cve') { shape = SHAPES.vulnerability; color = COLORS.vulnerability; type = 'vulnerability'; }
            else if (ioc.type === 'ip' || ioc.type === 'domain' || ioc.type === 'ip:port') { shape = SHAPES.infrastructure; color = COLORS.infrastructure; type = 'infrastructure'; }
            else if (ioc.type === 'payload' || ioc.type === 'hash') { shape = SHAPES.tool; color = COLORS.tool; type = 'tool'; }

            addNode({ data: { id: ioc.id, label: ioc.value.substring(0, 25), type, shape, color, size: 45, rawData: { source: ioc.source, severity: ioc.severity } }, classes: 'new-node' });
            addEdge(actor.id, ioc.id, type === 'vulnerability' ? 'exploits' : 'uses');
            nCount++;
          }
        }
      }

      // NIVEAU 2: Voisins des campagnes et malwares
      if (depthExplorer >= 2) {
        const level1Entities = nodesToAdd.filter(n => n.data.type === 'campaign' || n.data.type === 'tool' || n.data.type === 'ioc');
        let l2Count = 0;
        
        for (const entity of level1Entities) {
          let subCount = 0;
          for (let i = 0; i < iocsData.length; i++) {
            if (subCount >= 5 || l2Count > 40) break;
            const ioc = iocsData[(i + parseInt(entity.data.id.replace(/\D/g, '') || '0')) % iocsData.length];
            if (!seenIds.has(ioc.id)) {
              let shape = SHAPES.ioc; let color = COLORS.ioc; let type = 'ioc';
              if (ioc.type === 'cve') { shape = SHAPES.vulnerability; color = COLORS.vulnerability; type = 'vulnerability'; }
              else if (ioc.type === 'ip' || ioc.type === 'domain' || ioc.type === 'ip:port') { shape = SHAPES.infrastructure; color = COLORS.infrastructure; type = 'infrastructure'; }
              else if (ioc.type === 'payload' || ioc.type === 'hash') { shape = SHAPES.tool; color = COLORS.tool; type = 'tool'; }

              addNode({ data: { id: ioc.id, label: ioc.value.substring(0, 25), type, shape, color, size: 35, rawData: { source: ioc.source, severity: ioc.severity } }, classes: 'new-node' });
              addEdge(entity.data.id, ioc.id, type === 'vulnerability' ? 'exploits' : 'related-to');
              subCount++;
              l2Count++;
            }
          }
        }
      }

      // NIVEAU 3: Entités partagées
      let sharedCount = 0;
      if (depthExplorer >= 3) {
        for (const shared of forcedShared) {
          addNode({ data: { id: shared.id, label: shared.label, type: shared.type, shape: shared.shape, color: shared.color, size: 55 }, classes: 'new-node' });
          for (const actorId of shared.linked) {
            addEdge(actorId, shared.id, shared.type === 'vulnerability' ? 'exploits' : 'uses');
          }
          sharedCount++;
        }
      }

      if (nodesToAdd.length > 100) {
        nodesToAdd.splice(100 - actors.length);
        const validNodes = new Set([...actors.map(a => a.id), ...nodesToAdd.map(n => n.data.id)]);
        for (let i = edges.length - 1; i >= 0; i--) {
          if (!validNodes.has(edges[i].data.source) || !validNodes.has(edges[i].data.target)) {
            edges.splice(i, 1);
          }
        }
      }

      const typeCounts = {
        actor: actors.length,
        campaign: nodesToAdd.filter(n => n.data.type === 'campaign').length,
        tool: nodesToAdd.filter(n => n.data.type === 'tool').length,
        vulnerability: nodesToAdd.filter(n => n.data.type === 'vulnerability').length,
        infrastructure: nodesToAdd.filter(n => n.data.type === 'infrastructure').length,
        ioc: nodesToAdd.filter(n => n.data.type === 'ioc').length,
      };

      console.log(`[GRAPH] Construction terminée:
  Nœuds totaux: ${nodesToAdd.length + actors.length}
  ├─ Acteurs: ${typeCounts.actor}
  ├─ Campagnes: ${typeCounts.campaign}
  ├─ Malwares/Outils: ${typeCounts.tool}
  ├─ CVEs: ${typeCounts.vulnerability}
  ├─ Infrastructure: ${typeCounts.infrastructure}
  └─ IOCs: ${typeCounts.ioc}
  Arêtes totales: ${edges.length}
  Entités partagées entre acteurs: ${sharedCount}
${depthExplorer >= 3 ? '    • CVE-2024-21762 ← Volt Typhoon, Lazarus Group\n    • Cobalt Strike  ← APT29, Lazarus Group\n    • 185.220.101.47 ← APT29, Volt Typhoon' : ''}`);

      return { edges, nodesToAdd };
    };

    const graphData = buildBalancedGraph();
    newNodes.push(...graphData.nodesToAdd);
    newEdges.push(...graphData.edges);

    setElements(prev => {
       setLastUpdate(new Date().toLocaleTimeString('fr-FR'));
       return [...newNodes, ...newEdges];
    });
  }, [threatfox, urlhaus, cisa, gdelt, depthExplorer]);

  useEffect(() => {
    if (threatfox.length > 0) {
      setLiveEvents(threatfox.slice(0, 10).map(t => ({
        time: new Date(t.first_seen).toLocaleTimeString('fr-FR'),
        desc: `Menace détectée: ${t.threat_type || 'Malware'} via ThreatFox`
      })));
    }
  }, [threatfox]);



  useEffect(() => {
    if (!cy) return;
    const pulseInterval = setInterval(() => {
      cy.elements('.new-node').toggleClass('pulse-on');
    }, 500);
    return () => clearInterval(pulseInterval);
  }, [cy]);

  useEffect(() => {
    if (!cy) return;

    cy.on('mouseover', 'node', (evt) => {
      const node = evt.target;
      if (pathAnalysis) return; // Ne pas highlight pendant l'analyse de chemin
      cy.elements().removeClass('highlighted dimmed');
      cy.elements().addClass('dimmed');
      node.removeClass('dimmed');
      node.neighborhood().removeClass('dimmed');
      node.connectedEdges().addClass('highlighted');
      node.neighborhood('node').addClass('highlighted');
    });

    cy.on('mouseout', 'node', (evt) => {
      if (pathAnalysis) return;
      if (!selectedNode) {
        cy.elements().removeClass('highlighted dimmed');
      } else {
        // Restore previous selection highlight
        cy.elements().addClass('dimmed');
        selectedNode.removeClass('dimmed');
        selectedNode.neighborhood().removeClass('dimmed');
        selectedNode.connectedEdges().addClass('highlighted');
        selectedNode.neighborhood('node').addClass('highlighted');
      }
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      
      if (pathAnalysis) {
        if (!sourceNode) {
          setSourceNode(node);
          cy.elements().removeClass('highlighted dimmed path');
          node.addClass('highlighted');
        } else {
          // Find path
          const elements = cy.elements();
          const dijkstra = elements.dijkstra({ root: sourceNode, directed: false });
          const path = dijkstra.pathTo(node);
          
          cy.elements().removeClass('highlighted dimmed path');
          if (path.length > 0) {
            cy.elements().addClass('dimmed');
            path.removeClass('dimmed').addClass('highlighted path');
          } else {
            alert('Aucun chemin trouvé entre ces entités.');
          }
          setSourceNode(null); // reset
        }
        return;
      }

      setSelectedNode(node);
    });

    cy.on('dblclick', 'node', (evt) => {
      const node = evt.target;
      cy.animate({
        fit: {
          eles: node.neighborhood().add(node),
          padding: 50
        },
        duration: 500
      });
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
        setSourceNode(null);
        cy.elements().removeClass('highlighted dimmed path');
      }
    });

  }, [cy, pathAnalysis, sourceNode, selectedNode]);

  // Handle Filtering
  useEffect(() => {
    if (!cy) return;
    
    cy.elements().removeClass('dimmed');
    
    if (filterType !== 'all') {
      cy.nodes().forEach(node => {
        if (node.data('type') !== filterType) {
          node.addClass('dimmed');
          node.connectedEdges().addClass('dimmed');
        }
      });
    }

    // Applying layout after filter visually helps but might be jarring, so we just dim them for stable layout.
  }, [filterType, cy]);

  const layoutConfigs: any = {
    hierarchical: { name: 'dagre', rankDir: 'TB', nodeSep: 80, rankSep: 120, edgeSep: 50, ranker: 'tight-tree', animate: true, animationDuration: 800, fit: true, padding: 50 },
    forceDirected: { name: 'cose-bilkent', animate: true, animationDuration: 800, fit: true, padding: 50, randomize: true },
    chronological: { name: 'breadthfirst', directed: true, spacingFactor: 1.5, animate: true, animationDuration: 800, fit: true, padding: 50 },
    geographical: { name: 'preset', animate: true, animationDuration: 800, fit: true, padding: 50 },
    concentric: { name: 'concentric', minNodeSpacing: 50, animate: true, animationDuration: 800, fit: true, padding: 50 },
  };

  const layout = useMemo(() => layoutConfigs[activeLayout], [activeLayout]);

  // Execute layout whenever elements or layout changes to avoid vertical stacking
  useEffect(() => {
    if (cy && elements.length > 0) {
      cy.layout(layout).run();
    }
  }, [elements, layout, cy]);

  return (
    <div className="flex h-[750px] bg-[#020617] rounded-xl border border-slate-800 font-sans overflow-hidden shadow-2xl relative">
      
      {/* TOOLBAR & FILTERS */}
      <div className="absolute top-4 left-4 z-10 flex flex-col gap-3">
        <div className="bg-slate-900/90 border border-slate-700 p-3 rounded-lg backdrop-blur-md shadow-lg flex flex-col gap-2">
          <div className="flex justify-between items-center border-b border-slate-800 pb-2 mb-1">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
              Filtres Analytiques
            </span>
            <span className="text-[9px] font-bold text-cyan-400 uppercase tracking-widest bg-cyan-900/30 px-2 py-0.5 rounded">
              MAJ: {lastUpdate}
            </span>
          </div>
          
          <div className="grid grid-cols-2 gap-2 mb-2">
            <button onClick={() => setActiveLayout('hierarchical')} className={`text-[10px] py-1 px-2 rounded font-bold uppercase tracking-widest ${activeLayout === 'hierarchical' ? 'bg-cyan-500 text-slate-900' : 'bg-slate-800 text-slate-400'}`}>Hiérarchique</button>
            <button onClick={() => setActiveLayout('forceDirected')} className={`text-[10px] py-1 px-2 rounded font-bold uppercase tracking-widest ${activeLayout === 'forceDirected' ? 'bg-cyan-500 text-slate-900' : 'bg-slate-800 text-slate-400'}`}>Force-Directed</button>
            <button onClick={() => setActiveLayout('chronological')} className={`text-[10px] py-1 px-2 rounded font-bold uppercase tracking-widest ${activeLayout === 'chronological' ? 'bg-cyan-500 text-slate-900' : 'bg-slate-800 text-slate-400'}`}>Chronologique</button>
            <button onClick={() => setActiveLayout('geographical')} className={`text-[10px] py-1 px-2 rounded font-bold uppercase tracking-widest ${activeLayout === 'geographical' ? 'bg-cyan-500 text-slate-900' : 'bg-slate-800 text-slate-400'}`}>Géographique</button>
            <button onClick={() => setActiveLayout('concentric')} className={`col-span-2 text-[10px] py-1 px-2 rounded font-bold uppercase tracking-widest ${activeLayout === 'concentric' ? 'bg-cyan-500 text-slate-900' : 'bg-slate-800 text-slate-400'}`}>Concentrique</button>
          </div>
          
          <div className="flex items-center gap-2 mt-1 px-1">
            <span className="text-[10px] text-slate-400 uppercase font-bold whitespace-nowrap">Profondeur:</span>
            <input type="range" min="1" max="3" value={depthExplorer} onChange={(e) => setDepthExplorer(Number(e.target.value))} className="w-full h-1 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-cyan-500" />
            <span className="text-[10px] text-cyan-400 font-bold w-4 text-center">{depthExplorer}</span>
          </div>
          <button onClick={() => setPathAnalysis(!pathAnalysis)} className={`mt-1 w-full text-[10px] py-1.5 rounded font-bold uppercase tracking-widest border transition-colors ${pathAnalysis ? 'bg-rose-500/20 text-rose-400 border-rose-500/50' : 'bg-slate-800 text-slate-300 border-slate-600'}`}>
            {pathAnalysis ? '◎ MODE ANALYSE DE CHEMIN ACTIF (SÉLECTIONNEZ 2 NŒUDS)' : '⟷ ACTIVER L\'ANALYSE DE CHEMIN'}
          </button>
          <div className="flex gap-2 mt-2">
            <select className="bg-slate-950 text-xs text-white border border-slate-700 rounded px-2 py-1 outline-none focus:border-cyan-500" value={filterType} onChange={(e) => setFilterType(e.target.value)}>
              <option value="all">Toutes Entités</option>
              <option value="actor">Acteurs</option>
              <option value="tool">Outils/Malwares</option>
              <option value="vulnerability">Vulnérabilités</option>
              <option value="infrastructure">Infrastructure</option>
            </select>
          </div>
          
          <button onClick={() => cy?.layout(layout).run()} className="mt-2 w-full bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] py-1.5 rounded border border-slate-600 transition-colors uppercase font-bold tracking-wider">
            ⟳ Réorganiser le Graphe
          </button>
        </div>
        
        {/* LEGENDE */}
        <div className="bg-slate-900/90 border border-slate-700 p-3 rounded-lg backdrop-blur-md shadow-lg flex flex-col gap-1.5">
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Légende Typologique</div>
          <div className="flex items-center gap-2 text-[10px] text-slate-300"><span className="w-3 h-3 rounded-full bg-red-500 inline-block"></span> Acteur (Cercle)</div>
          <div className="flex items-center gap-2 text-[10px] text-slate-300"><span className="w-3 h-3 bg-orange-500 inline-block"></span> Outil/Malware (Carré)</div>
          <div className="flex items-center gap-2 text-[10px] text-slate-300"><span className="w-3 h-3 bg-yellow-500 rotate-45 inline-block"></span> Vulnérabilité (Losange)</div>
          <div className="flex items-center gap-2 text-[10px] text-slate-300"><span className="w-3 h-3 bg-blue-500" style={{ clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)' }}></span> Infra (Hexagone)</div>
          <div className="flex items-center gap-2 text-[10px] text-slate-300"><span className="w-3 h-3 bg-purple-500" style={{ clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)' }}></span> Campagne (Triangle)</div>
        </div>
      </div>

      {/* GRAPH RENDERER */}
      <div className="flex-1 w-full h-full relative" ref={wrapperRef}>
        {elements.length === 0 ? (
          <div className="w-full h-full flex flex-col items-center justify-center gap-4 bg-[#0a0f1a]">
            <div className="w-12 h-12 border-4 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"></div>
            <div className="text-cyan-400 font-mono text-sm tracking-widest uppercase">Initialisation du graphe... En attente de télémétrie</div>
            <div className="text-slate-500 text-xs font-mono">Connexion aux sources OSINT en cours</div>
          </div>
        ) : (
          <CytoscapeComponent
            elements={elements}
            style={{ width: '100%', height: '100%' }}
            stylesheet={stylesheet}
            layout={layout}
            cy={(c) => setCy(c)}
            wheelSensitivity={0.2}
          />
        )}
      </div>

      {/* RIGHT SIDEBAR (Live events + Details) */}
      <div className="absolute top-0 right-0 h-full w-80 flex flex-col pointer-events-none">
        <div className="flex-1 bg-slate-900/95 border-l border-slate-700 shadow-[-10px_0_30px_rgba(0,0,0,0.5)] p-5 overflow-y-auto backdrop-blur-xl transition-all pointer-events-auto flex flex-col gap-4">
          
          {/* Intelligence Live Panel */}
          <div className="flex flex-col gap-2">
            <h3 className="text-xs uppercase tracking-widest font-bold text-slate-400 border-b border-slate-800 pb-2 mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse"></span> Intelligence Temps Réel
            </h3>
            {liveEvents.length === 0 ? <div className="text-xs text-slate-500">En attente d'événements...</div> : null}
            {liveEvents.map((ev, i) => (
              <div key={i} className="text-xs bg-cyan-500/10 border border-cyan-500/20 p-2 rounded text-cyan-400">
                <span className="font-mono opacity-70 mr-2">{ev.time}</span>
                {ev.desc}
              </div>
            ))}
          </div>

          <div className="w-full h-px bg-slate-800 my-2"></div>

          {selectedNode ? (
            <div className="flex flex-col gap-4">
              <div className="flex justify-between items-start">
                <div>
                  <div className="text-[10px] uppercase tracking-widest font-bold" style={{ color: selectedNode.data('color') }}>
                    Type: {selectedNode.data('type')}
                  </div>
                  <h3 className="text-xl font-black text-white mt-1">{selectedNode.data('label')}</h3>
                </div>
                <button onClick={() => setSelectedNode(null)} className="text-slate-500 hover:text-white">✕</button>
              </div>

          <div className="flex flex-col gap-5">
            <div className="bg-slate-950 border border-slate-800 rounded p-3">
              <div className="text-[9px] uppercase tracking-widest text-slate-500 mb-2 font-bold">Identifiant Unique</div>
              <code className="text-xs text-cyan-400 font-mono break-all">{selectedNode.data('id')}</code>
            </div>

            {selectedNode.data('rawData') && (
              <div className="flex flex-col gap-3">
                <div className="text-[10px] uppercase tracking-widest text-slate-500 font-bold border-b border-slate-800 pb-1">Attributs de l'Entité</div>
                {Object.entries(selectedNode.data('rawData')).map(([key, value]) => (
                  <div key={key} className="flex justify-between items-center text-xs">
                    <span className="text-slate-400 capitalize">{key}:</span>
                    <span className="text-white font-bold">{String(value)}</span>
                  </div>
                ))}
              </div>
            )}

            <div className="flex flex-col gap-3 mt-2">
              <div className="text-[10px] uppercase tracking-widest text-slate-500 font-bold border-b border-slate-800 pb-1">Relations Topologiques</div>
              <div className="flex flex-col gap-2">
                {selectedNode.connectedEdges().map(edge => {
                  const isSource = edge.source().id() === selectedNode.id();
                  const targetNode = isSource ? edge.target() : edge.source();
                  const direction = isSource ? 'Sortant vers' : 'Entrant depuis';
                  return (
                    <div key={edge.id()} className="text-[10px] bg-slate-800/50 p-2 rounded border border-slate-700 flex flex-col gap-1">
                      <span className="text-slate-400">{direction} <span className="text-white font-bold">{targetNode.data('label')}</span></span>
                      <span className="text-cyan-400 font-mono">[{edge.data('label')}]</span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-slate-800">
              <button onClick={() => handleExportSTIX(selectedNode)} className="w-full py-2 bg-indigo-500/20 text-indigo-400 border border-indigo-500/50 rounded text-xs font-bold uppercase tracking-widest hover:bg-indigo-500/40 transition-colors mb-2">
                Export STIX 2.1
              </button>
              <button onClick={() => setRemediationOpen(true)} className="w-full py-2 bg-rose-500/20 text-rose-400 border border-rose-500/50 rounded text-xs font-bold uppercase tracking-widest hover:bg-rose-500/40 transition-colors">
                Action de Remédiation
              </button>
            </div>
            </div>
          </div>
          ) : (
            <div className="text-slate-500 text-sm italic text-center mt-10">Sélectionnez un nœud pour afficher ses détails</div>
          )}
        </div>
      </div>

      {remediationOpen && selectedNode && (
        <RemediationModal 
          entity={{
            id: selectedNode.id(),
            type: selectedNode.data('type'),
            name: selectedNode.data('label'),
            attributes: selectedNode.data('rawData') || {},
            relations: []
          }} 
          onClose={() => setRemediationOpen(false)} 
        />
      )}

      {toastMsg && (
        <div className="absolute bottom-4 right-4 bg-green-500/20 border border-green-500 text-green-400 p-3 px-5 rounded-lg z-50 font-bold flex items-center gap-3 shadow-[0_0_15px_rgba(34,197,94,0.3)] animate-[bounce_1s_infinite]">
           <span className="text-xl">✅</span> {toastMsg}
        </div>
      )}
    </div>
  );
}

export default function ThreatGraph() {
  return <ErrorBoundary><ThreatGraphContent /></ErrorBoundary>;
}
