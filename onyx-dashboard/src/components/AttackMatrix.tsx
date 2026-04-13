'use client';

import { useEffect, useState, useMemo } from 'react';
import SlideOver from './SlideOver';
const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const TACTICS = [
  { id: 'reconnaissance',       name: 'Reconnaissance',       shortName: 'RECON' },
  { id: 'resource-development',  name: 'Resource Development',  shortName: 'RES.DEV' },
  { id: 'initial-access',        name: 'Initial Access',        shortName: 'INIT.ACC' },
  { id: 'execution',             name: 'Execution',             shortName: 'EXEC' },
  { id: 'persistence',           name: 'Persistence',           shortName: 'PERSIST' },
  { id: 'privilege-escalation',  name: 'Privilege Escalation',  shortName: 'PRIV.ESC' },
  { id: 'defense-evasion',       name: 'Defense Evasion',       shortName: 'DEF.EVA' },
  { id: 'credential-access',     name: 'Credential Access',     shortName: 'CRED.ACC' },
  { id: 'discovery',             name: 'Discovery',             shortName: 'DISC' },
  { id: 'lateral-movement',      name: 'Lateral Movement',      shortName: 'LAT.MOV' },
  { id: 'collection',            name: 'Collection',            shortName: 'COLL' },
  { id: 'command-and-control',   name: 'Command & Control',     shortName: 'C&C' },
  { id: 'exfiltration',          name: 'Exfiltration',          shortName: 'EXFIL' },
  { id: 'impact',                name: 'Impact',                shortName: 'IMPACT' },
];

const TECHNIQUES_BY_TACTIC: Record<string, Array<{ id: string; name: string }>> = {
  'reconnaissance': [{id: 'T1595', name: 'Active Scanning'}, {id: 'T1592', name: 'Host Info'}, {id: 'T1589', name: 'Identity'}, {id: 'T1590', name: 'Network'}, {id: 'T1591', name: 'Org Info'}, {id: 'T1598', name: 'Phishing for Info'}],
  'resource-development': [{id: 'T1583', name: 'Acquire Infra'}, {id: 'T1586', name: 'Compromise Accts'}, {id: 'T1584', name: 'Compromise Infra'}, {id: 'T1587', name: 'Dev Capabilities'}, {id: 'T1585', name: 'Establish Accts'}, {id: 'T1588', name: 'Obtain Capabilities'}],
  'initial-access': [{id: 'T1189', name: 'Drive-by'}, {id: 'T1190', name: 'Exploit Public App'}, {id: 'T1133', name: 'Ext Remote Svcs'}, {id: 'T1566', name: 'Phishing'}, {id: 'T1091', name: 'Rep via Media'}, {id: 'T1195', name: 'Supply Chain'}, {id: 'T1199', name: 'Trusted Relation'}, {id: 'T1078', name: 'Valid Accounts'}],
  'execution': [{id: 'T1059', name: 'Cmd & Script'}, {id: 'T1203', name: 'Exploitation'}, {id: 'T1559', name: 'IPC'}, {id: 'T1106', name: 'Native API'}, {id: 'T1053', name: 'Scheduled Task'}, {id: 'T1129', name: 'Shared Modules'}, {id: 'T1204', name: 'User Execution'}, {id: 'T1047', name: 'WMI'}],
  'persistence': [{id: 'T1098', name: 'Acct Manipulation'}, {id: 'T1547', name: 'Boot Autostart'}, {id: 'T1136', name: 'Create Account'}, {id: 'T1543', name: 'Create/Modify Proc'}, {id: 'T1546', name: 'Event Triggered'}, {id: 'T1574', name: 'Hijack Execution'}, {id: 'T1053', name: 'Scheduled Task'}, {id: 'T1505', name: 'Server Software'}],
  'privilege-escalation': [{id: 'T1548', name: 'Abuse Elevation'}, {id: 'T1134', name: 'Token Manipulation'}, {id: 'T1547', name: 'Boot Autostart'}, {id: 'T1068', name: 'Exploitation'}, {id: 'T1055', name: 'Process Injection'}, {id: 'T1078', name: 'Valid Accounts'}],
  'defense-evasion': [{id: 'T1140', name: 'Deobfuscate'}, {id: 'T1070', name: 'Indicator Removal'}, {id: 'T1036', name: 'Masquerading'}, {id: 'T1027', name: 'Obfuscated Files'}, {id: 'T1055', name: 'Process Injection'}, {id: 'T1218', name: 'System Bin Proxy'}, {id: 'T1112', name: 'Modify Registry'}],
  'credential-access': [{id: 'T1110', name: 'Brute Force'}, {id: 'T1555', name: 'Creds from Stores'}, {id: 'T1212', name: 'Exploitation'}, {id: 'T1187', name: 'Forced Auth'}, {id: 'T1003', name: 'OS Cred Dumping'}, {id: 'T1528', name: 'Steal App Token'}],
  'discovery': [{id: 'T1087', name: 'Account Discovery'}, {id: 'T1083', name: 'File & Dir'}, {id: 'T1046', name: 'Network Svc'}, {id: 'T1057', name: 'Process Discovery'}, {id: 'T1082', name: 'System Info'}, {id: 'T1016', name: 'Network Config'}],
  'lateral-movement': [{id: 'T1210', name: 'Exploitation'}, {id: 'T1534', name: 'Internal Spearphish'}, {id: 'T1570', name: 'Lateral Tool Trans'}, {id: 'T1021', name: 'Remote Services'}, {id: 'T1080', name: 'Taint Shared Content'}],
  'collection': [{id: 'T1560', name: 'Archive Data'}, {id: 'T1119', name: 'Automated Collect'}, {id: 'T1005', name: 'Local System'}, {id: 'T1039', name: 'Network Share'}, {id: 'T1114', name: 'Email Collection'}, {id: 'T1113', name: 'Screen Capture'}],
  'command-and-control': [{id: 'T1071', name: 'App Layer Protocol'}, {id: 'T1132', name: 'Data Encoding'}, {id: 'T1001', name: 'Data Obfuscation'}, {id: 'T1573', name: 'Encrypted Channel'}, {id: 'T1105', name: 'Ingress Tool Trans'}, {id: 'T1572', name: 'Protocol Tunnel'}],
  'exfiltration': [{id: 'T1020', name: 'Auto Exfiltration'}, {id: 'T1048', name: 'Exfil Alt Protocol'}, {id: 'T1041', name: 'Exfil C2 Channel'}, {id: 'T1567', name: 'Exfil Web Svc'}, {id: 'T1537', name: 'Trans Cloud Acct'}],
  'impact': [{id: 'T1531', name: 'Acct Access Removal'}, {id: 'T1485', name: 'Data Destruction'}, {id: 'T1486', name: 'Data Encrypted'}, {id: 'T1565', name: 'Data Manipulation'}, {id: 'T1491', name: 'Defacement'}, {id: 'T1561', name: 'Disk Wipe'}, {id: 'T1489', name: 'Service Stop'}, {id: 'T1490', name: 'Inhibit Recovery'}],
};

interface TechniqueData {
  technique_id: string;
  count: number;
  avg_confidence: number;
  severity_breakdown: Record<string, number>;
}

interface ThreatActor {
  id: string;
  name: string;
  description: string;
  techniques: string[];
}

interface PedagogyData {
  name: string;
  explanation: string;
  impact: string;
  example?: string;
  mitigation: string;
}

function heatColor(count: number, maxCount: number): string {
  if (count === 0) return 'rgba(30, 41, 59, 0.4)'; // Dimmed background
  const intensity = Math.min(count / Math.max(maxCount, 1), 1);
  if (intensity < 0.25) return `rgba(0, 240, 255, ${0.1 + intensity * 0.6})`;
  if (intensity < 0.5) return `rgba(0, 240, 255, ${0.25 + intensity * 0.8})`;
  if (intensity < 0.75) return `rgba(255, 170, 0, ${0.3 + intensity * 0.7})`;
  return `rgba(255, 59, 92, ${0.5 + intensity * 0.5})`;
}

export default function AttackMatrix() {
  const [heatmapData, setHeatmapData] = useState<Record<string, TechniqueData>>({});
  const [threatActors, setThreatActors] = useState<ThreatActor[]>([]);
  const [selectedTA, setSelectedTA] = useState<string>('none');
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const [pedagogy, setPedagogy] = useState<PedagogyData | null>(null);
  const [loading, setLoading] = useState(true);
  const [briefingExpanded, setBriefingExpanded] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const resMap = await fetch(`${API}/api/v1/dashboard/mitre-heatmap`);
        if (resMap.ok) {
          const data = await resMap.json();
          const map: Record<string, TechniqueData> = {};
          for (const t of data.techniques || []) map[t.technique_id] = t;
          setHeatmapData(map);
        }
        
        const resTA = await fetch(`${API}/api/v1/dashboard/mitre-threat-actors`);
        if (resTA.ok) {
          const taData = await resTA.json();
          setThreatActors(taData.threat_actors || []);
        }
      } catch (e) {
        console.error("Failed to fetch matrix data", e);
      }
      setLoading(false);
    }
    loadData();
  }, []);

  useEffect(() => {
    if (!selectedTechnique) {
      setPedagogy(null);
      return;
    }
    setPedagogy(null); // Clear loading state
    async function fetchPedagogy() {
      try {
        const res = await fetch(`${API}/api/v1/dashboard/mitre-pedagogy/${selectedTechnique}`);
        if (res.ok) setPedagogy(await res.json());
      } catch (e) {
        console.error("Failed to fetch pedagogy", e);
      }
    }
    fetchPedagogy();
  }, [selectedTechnique]);

  const maxCount = useMemo(() => Math.max(1, ...Object.values(heatmapData).map(t => t.count)), [heatmapData]);
  const maxTechsPerColumn = useMemo(() => Math.max(...Object.values(TECHNIQUES_BY_TACTIC).map(t => t.length)), []);

  const activeTATechniques = useMemo(() => {
    if (selectedTA === 'none') return new Set();
    const ta = threatActors.find(t => t.id === selectedTA);
    return new Set(ta?.techniques || []);
  }, [selectedTA, threatActors]);

  if (loading) return <div className="onyx-card loading-shimmer" style={{ height: '600px' }} />;

  return (
    <div className="onyx-card relative flex flex-col gap-4 overflow-hidden" style={{ padding: 'var(--space-md)' }}>
      {/* ── Phase 1: Intelligence Briefing Header ── */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-lg overflow-hidden">
        <div 
          className="px-4 py-3 bg-[#1e293b] cursor-pointer flex justify-between items-center"
          onClick={() => setBriefingExpanded(!briefingExpanded)}
        >
          <h3 className="font-bold text-[#00eeff] flex items-center gap-2">
            <span className="text-xl">🛡</span> Intelligence Briefing & MITRE Heatmap
          </h3>
          <span className="text-[#94a3b8] text-xs font-mono">{briefingExpanded ? '▲ COLLAPSE' : '▼ EXPAND'}</span>
        </div>
        {briefingExpanded && (
          <div className="p-4 text-sm text-[#cbd5e1] flex flex-col gap-3">
            <p>
              <strong className="text-white">Expert Context:</strong> This matrix dynamically aggregates live IOC metadata mapping it to the MITRE ATT&CK Enterprise framework. Cellular hue intensity directly correlates to the aggregate severity and frequency of techniques extracted via NLP and OSINT real-time inference over the last 24 hours.
            </p>
            <p className="text-xs text-[#94a3b8] border-l-2 border-[#00eeff] pl-3 py-1">
              <strong className="text-white">Beginner Guide:</strong> Think of the columns as the "Goals" a hacker has (like getting in, hiding, or stealing data), and the cells as the specific "Techniques" they use to achieve those goals. Red glowing cells mean we are detecting these techniques <em>right now</em> on our network or in global threat feeds.
            </p>
          </div>
        )}
      </div>

      {/* ── Phase 3: TA Overlay Controls ── */}
      <div className="flex justify-between items-end bg-[#050a0f] p-3 rounded border border-[#1e293b]">
        <div className="flex items-center gap-4">
          <div>
            <div className="text-[10px] uppercase text-[#64748b] font-bold mb-1">Threat Actor Overlay</div>
            <select 
              value={selectedTA} 
              onChange={(e) => setSelectedTA(e.target.value)}
              className="bg-[#0f172a] border border-[#334155] text-white text-xs px-3 py-1.5 rounded outline-none w-48 font-mono"
            >
              <option value="none">-- Select Actor to Overlay --</option>
              {threatActors.map(ta => (
                <option key={ta.id} value={ta.id}>{ta.name} ({ta.description})</option>
              ))}
            </select>
          </div>
          {selectedTA !== 'none' && (
            <div className="px-3 py-1 bg-purple-900/20 border border-purple-500/40 rounded text-[10px] text-purple-300 font-mono flex items-center h-8 mt-4">
              <span className="w-2 h-2 rounded-full bg-purple-500 animate-pulse mr-2 shadow-[0_0_8px_#a855f7]"></span>
              Hypothesis Overlay Active
            </div>
          )}
        </div>
        
        {/* Heat scale legend */}
        <div className="flex items-center gap-2 text-[10px] text-[#64748b]">
          <span>Low Detections</span>
          <div className="flex gap-0.5">
            {[0, 0.3, 0.5, 0.7, 0.9].map((i) => (
              <div key={i} className="w-4 h-2.5 rounded-sm" style={{ background: heatColor(i * 100, 100) }} />
            ))}
          </div>
          <span>High Detections</span>
        </div>
      </div>

      {/* ── Phase 3: Matrix Grid ── */}
      <div className="overflow-x-auto pb-4 scrollbar-hide">
        <div style={{ display: 'grid', gridTemplateColumns: `repeat(${TACTICS.length}, minmax(100px, 1fr))`, gap: '4px', fontFamily: 'var(--font-mono)' }}>
          {/* Tactic Headers */}
          {TACTICS.map(tactic => (
            <div key={tactic.id} className="p-2 text-center text-[10px] font-extrabold text-[#00eeff] bg-[#0f172a] rounded-t-md border-b-2 border-[#1e293b] truncate">
              {tactic.shortName}
            </div>
          ))}

          {/* Technique Cells */}
          {Array.from({ length: maxTechsPerColumn }).map((_, rowIdx) => (
            TACTICS.map(tactic => {
              const techniques = TECHNIQUES_BY_TACTIC[tactic.id] || [];
              const tech = techniques[rowIdx];
              if (!tech) return <div key={`${tactic.id}-${rowIdx}`} className="min-h-[36px]" />;

              const data = heatmapData[tech.id];
              const count = data?.count || 0;
              const isSelected = selectedTechnique === tech.id;
              const isTAHighlighted = activeTATechniques.has(tech.id);

              return (
                <div
                  key={`${tactic.id}-${tech.id}`}
                  onClick={() => setSelectedTechnique(isSelected ? null : tech.id)}
                  style={{ background: heatColor(count, maxCount) }}
                  // Neon border for TA Overlay logic
                  className={`
                    flex flex-col justify-center p-1.5 rounded text-[9.5px] cursor-pointer transition-all duration-300 min-h-[36px] relative overflow-hidden group
                    ${count > 0 ? 'text-white' : 'text-[#64748b]'}
                    ${isSelected ? 'ring-2 ring-[#00eeff] bg-opacity-80 scale-[1.02]' : ''}
                    ${isTAHighlighted ? 'border-2 border-purple-500 shadow-[0_0_12px_rgba(168,85,247,0.5)] z-10 scale-[1.01]' : 'border border-transparent'}
                    hover:border-[#00eeff] hover:opacity-100
                  `}
                  title={`${tech.id}: ${tech.name}\n${count > 0 ? `⚠️ ACTIVITÉ DÉTECTÉE : ${count} événements liés actuellement en direct.` : 'Aucune activité live pour le moment.'}\nCliquez pour voir les recommandations, explications complètes et acteurs associés.`}
                >
                  <span className="font-bold truncate z-10">{tech.id}</span>
                  {count > 0 && (
                    <span className="text-[8px] text-[#cbd5e1] mt-0.5 font-bold z-10">{count} Events</span>
                  )}
                  {/* Subtle hover glow layer */}
                  <div className="absolute inset-0 bg-white/5 opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              );
            })
          )).flat()}
        </div>
      </div>

      {/* ── Phase 4: SlideOver Component mapped to MITRE endpoints ── */}
      <SlideOver 
        technique={selectedTechnique}
        onClose={() => setSelectedTechnique(null)}
        heatmapCount={selectedTechnique ? (heatmapData[selectedTechnique]?.count || 0) : 0}
        avgConfidence={selectedTechnique ? (heatmapData[selectedTechnique]?.avg_confidence || 0) : 0}
      />
    </div>
  );
}
