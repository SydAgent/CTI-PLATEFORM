'use client';
import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';

// ─── Domain Types ────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface EventHit {
  id: string;
  severity: Severity;
  context: string;
  sourceIp?: string;
  ts: number;
}

export interface NLPEntity {
  text: string;
  type: 'actor' | 'ttp' | 'malware' | 'cve' | 'org' | 'infra';
  confidence: number;
  start: number;
  end: number;
}

export interface TTPObservation {
  id: string;          // e.g. T1059.001
  name: string;
  tactic: string;
  confidence: number;
  ts: number;
  sourceActors: string[];
}

export interface ActorProfile {
  id: string;
  name: string;
  motivation: string;
  sector: string;
  riskScore: number;
  trend: 'up' | 'down' | 'stable';
  ttps: string[];
  businessImpact: string;
  category: 'nation-state' | 'eCrime' | 'hacktivist';
  lastSeen: number;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'actor' | 'ip' | 'malware' | 'ttp';
  severity?: Severity;
}

export interface GraphEdge {
  source: string;
  target: string;
  label?: string;
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  lastSyncTs: number;
}

export interface StixBundle {
  id: string;
  type: 'bundle';
  objects: StixObject[];
}

export interface StixObject {
  id: string;
  type: string;
  name?: string;
  description?: string;
  created: string;
  modified: string;
  [key: string]: unknown;
}

export interface ReportBlock {
  id: string;
  title: string;
  severity: Severity;
  summary: string;
  recommendation: string;
  ts: number;
}

// ─── Store Interface ──────────────────────────────────────────────────────────

interface OmegaState {
  // Detection Engineering
  ruleText: string;
  isSimulating: boolean;
  hits: EventHit[];
  setRuleText: (text: string) => void;
  runSimulation: () => void;

  // Report View
  reportViewMode: 'Technical' | 'Executive';
  setReportViewMode: (mode: 'Technical' | 'Executive') => void;

  // Telemetry / Severity
  severityDistribution: SeverityDistribution;
  setSeverityDistribution: (dist: Partial<SeverityDistribution>) => void;

  // NLP / SciBERT
  nlpInputText: string;
  nlpEntities: NLPEntity[];
  nlpIsAnalyzing: boolean;
  setNlpInputText: (text: string) => void;
  setNlpEntities: (entities: NLPEntity[]) => void;
  setNlpIsAnalyzing: (v: boolean) => void;

  // TTP observations (drives AI Lab scenarios)
  recentTTPs: TTPObservation[];
  addTTPObservation: (ttp: TTPObservation) => void;
  setRecentTTPs: (ttps: TTPObservation[]) => void;

  // Threat Actors
  threatActors: ActorProfile[];
  setThreatActors: (actors: ActorProfile[]) => void;

  // Threat Graph
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
  setGraphData: (nodes: GraphNode[], edges: GraphEdge[]) => void;

  // Report blocks (reactive)
  reportBlocks: ReportBlock[];
  setReportBlocks: (blocks: ReportBlock[]) => void;
  updateReportBlockSeverity: (id: string, severity: Severity) => void;

  // STIX Export
  stixBundle: StixBundle | null;
  setStixBundle: (bundle: StixBundle | null) => void;

  // Global sync timestamp
  lastGlobalSync: number;
  tickSync: () => void;
}

// ─── Store Implementation ─────────────────────────────────────────────────────

export const useOmegaStore = create<OmegaState>()(
  subscribeWithSelector((set) => ({
    // Detection
    ruleText: '',
    isSimulating: false,
    hits: [],
    setRuleText: (text) => set({ ruleText: text }),
    runSimulation: () => {
      set({ isSimulating: true });
      setTimeout(() => {
        set((state) => ({
          isSimulating: false,
          hits: state.hits.length === 0
            ? []   // Real hits come from API; no mock injection
            : state.hits,
        }));
      }, 800);
    },

    // Report
    reportViewMode: 'Executive',
    setReportViewMode: (mode) => set({ reportViewMode: mode }),

    // Telemetry
    severityDistribution: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0,
      lastSyncTs: Date.now(),
    },
    setSeverityDistribution: (dist) =>
      set((s) => ({
        severityDistribution: { ...s.severityDistribution, ...dist, lastSyncTs: Date.now() },
      })),

    // NLP
    nlpInputText: '',
    nlpEntities: [],
    nlpIsAnalyzing: false,
    setNlpInputText: (text) => set({ nlpInputText: text }),
    setNlpEntities: (entities) => set({ nlpEntities: entities }),
    setNlpIsAnalyzing: (v) => set({ nlpIsAnalyzing: v }),

    // TTPs
    recentTTPs: [],
    addTTPObservation: (ttp) =>
      set((s) => ({ recentTTPs: [ttp, ...s.recentTTPs].slice(0, 20) })),
    setRecentTTPs: (ttps) => set({ recentTTPs: ttps }),

    // Threat Actors
    threatActors: [],
    setThreatActors: (actors) => set({ threatActors: actors }),

    // Graph
    graphNodes: [],
    graphEdges: [],
    setGraphData: (nodes, edges) => set({ graphNodes: nodes, graphEdges: edges }),

    // Report Blocks
    reportBlocks: [],
    setReportBlocks: (blocks) => set({ reportBlocks: blocks }),
    updateReportBlockSeverity: (id, severity) =>
      set((s) => ({
        reportBlocks: s.reportBlocks.map((b) =>
          b.id === id ? { ...b, severity, ts: Date.now() } : b
        ),
      })),

    // STIX
    stixBundle: null,
    setStixBundle: (bundle) => set({ stixBundle: bundle }),

    // Sync
    lastGlobalSync: Date.now(),
    tickSync: () => set({ lastGlobalSync: Date.now() }),
  }))
);
