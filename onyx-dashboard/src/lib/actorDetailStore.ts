import { create } from 'zustand';

// Density levels: 1=overview, 2=analyst, 3=expert
export type DensityLevel = 1 | 2 | 3;

interface ActorDetailState {
  // Cross-panel selection
  selectedNodeId: string | null;
  // Which MITRE techniques are highlighted (from orbital graph click)
  highlightedTechniques: string[];
  // Decay state filter applied to IoC table from graph
  filteredDecayState: string | null;
  // Progressive disclosure density level
  densityLevel: DensityLevel;
  // Brushed time range from timeline (ISO strings)
  brushedTimeRange: [string, string] | null;

  setSelectedNodeId: (id: string | null) => void;
  setHighlightedTechniques: (ids: string[]) => void;
  setFilteredDecayState: (state: string | null) => void;
  setDensityLevel: (level: DensityLevel) => void;
  setBrushedTimeRange: (range: [string, string] | null) => void;
  reset: () => void;
}

const INITIAL: Omit<ActorDetailState, keyof { [K in keyof ActorDetailState as ActorDetailState[K] extends (...args: any[]) => any ? K : never]: true }> = {
  selectedNodeId: null,
  highlightedTechniques: [],
  filteredDecayState: null,
  densityLevel: 2,
  brushedTimeRange: null,
};

export const useActorDetailStore = create<ActorDetailState>((set) => ({
  selectedNodeId: null,
  highlightedTechniques: [],
  filteredDecayState: null,
  densityLevel: 2,
  brushedTimeRange: null,

  setSelectedNodeId: (id) => set({ selectedNodeId: id }),
  setHighlightedTechniques: (ids) => set({ highlightedTechniques: ids }),
  setFilteredDecayState: (state) => set({ filteredDecayState: state }),
  setDensityLevel: (level) => set({ densityLevel: level }),
  setBrushedTimeRange: (range) => set({ brushedTimeRange: range }),
  reset: () => set({
    selectedNodeId: null,
    highlightedTechniques: [],
    filteredDecayState: null,
    brushedTimeRange: null,
  }),
}));
