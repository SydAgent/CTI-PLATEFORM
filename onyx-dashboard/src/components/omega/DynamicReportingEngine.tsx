"use client";
import React, { useMemo } from 'react';
import { useOmegaStore, ReportBlock, Severity } from '../../lib/store/omegaStore';

const SEV_STYLES: Record<Severity, { border: string; bg: string; text: string; glow: string }> = {
  critical: { border: 'border-rose-500',   bg: 'bg-rose-500/10',   text: 'text-rose-400',   glow: 'shadow-[inset_4px_0_0_#f43f5e]' },
  high:     { border: 'border-orange-500', bg: 'bg-orange-500/10', text: 'text-orange-400', glow: 'shadow-[inset_4px_0_0_#f97316]' },
  medium:   { border: 'border-yellow-500', bg: 'bg-yellow-500/10', text: 'text-yellow-400', glow: 'shadow-[inset_4px_0_0_#eab308]' },
  low:      { border: 'border-blue-500',   bg: 'bg-blue-500/10',   text: 'text-blue-400',   glow: 'shadow-[inset_4px_0_0_#3b82f6]' },
};

function LiveTicker() {
  return (
    <div className="w-full bg-indigo-600 text-white overflow-hidden whitespace-nowrap flex items-center py-1">
      <div className="animate-[slide_20s_linear_infinite] inline-block text-[9px] font-mono font-bold tracking-widest uppercase">
        *** CTEM LIVE EXPOSURE FEED *** NEW THREAT ACTOR SIGNATURES DETECTED *** ZERO-DAY VULNERABILITY IN EXTERNAL INFRASTRUCTURE *** UPDATE YARA RULESETS *** CTEM LIVE EXPOSURE FEED ***
      </div>
    </div>
  );
}

export default function DynamicReportingEngine() {
  const { reportBlocks } = useOmegaStore();

  const sorted = useMemo(() => {
    const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    return [...reportBlocks].sort((a, b) => {
      const p = order[a.severity] - order[b.severity];
      if (p !== 0) return p;
      return b.ts - a.ts;
    });
  }, [reportBlocks]);

  return (
    <div className="bg-[#050811] border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[600px]">
      <LiveTicker />
      <div className="px-6 py-4 bg-[#0a0f1c] border-b border-slate-800 flex justify-between items-end">
        <div>
          <h2 className="text-sm font-black text-white uppercase tracking-[0.2em] font-mono">Continuous Threat Exposure Feed</h2>
          <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mt-1">Real-time intelligence syndication</p>
        </div>
        <div className="flex gap-2">
           <span className="text-[10px] font-mono font-bold px-2 py-1 bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded uppercase">
             {sorted.filter(r => r.severity==='critical').length} Critical
           </span>
        </div>
      </div>
      
      <div className="flex-1 p-6 overflow-auto bg-[#03050a]">
        {sorted.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center gap-4 opacity-30">
            <span className="text-4xl filter grayscale">📡</span>
            <p className="text-xs font-mono font-bold text-slate-400 uppercase tracking-widest">No Intelligence Feeds Received</p>
          </div>
        ) : (
          <div className="space-y-4">
            {sorted.map(block => {
              const s = SEV_STYLES[block.severity];
              const age = Math.floor((Date.now() - block.ts)/60000);
              return (
                <div key={block.id} className={`p-5 bg-slate-900 border border-slate-800 rounded ${s.glow} hover:bg-slate-800/80 transition-colors`}>
                   <div className="flex justify-between items-start mb-3">
                      <div className="flex items-center gap-3">
                         <span className={`text-[10px] font-mono font-black uppercase tracking-widest px-2 py-0.5 border rounded ${s.bg} ${s.border} ${s.text}`}>
                           {block.severity}
                         </span>
                         <h3 className="text-sm font-bold text-white font-mono tracking-tight">{block.title}</h3>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 font-bold uppercase">{age < 1 ? 'Just now' : `${age}m ago`}</span>
                   </div>
                   <p className="text-xs text-slate-300 font-sans leading-relaxed mb-4 border-l-2 border-slate-700 pl-3">{block.summary}</p>
                   <div className="bg-indigo-950/30 border border-indigo-500/20 rounded p-3">
                     <p className="text-[9px] font-mono uppercase tracking-widest text-indigo-400 font-bold mb-1">CTEM Recommended Action</p>
                     <p className="text-xs text-slate-300 font-mono">{block.recommendation}</p>
                   </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
