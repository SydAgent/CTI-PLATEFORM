"use client";
import React, { useMemo } from 'react';
import { useOmegaStore, EventHit, Severity } from '../../lib/store/omegaStore';

const SEV_STYLES: Record<Severity, { bg: string; text: string; badge: string; shadow: string }> = {
  critical: { bg: 'bg-rose-500/10', text: 'text-rose-400', badge: 'bg-rose-500/20 border-rose-500/50', shadow: 'shadow-[inset_4px_0_0_#f43f5e]' },
  high:     { bg: 'bg-orange-500/10', text: 'text-orange-400', badge: 'bg-orange-500/20 border-orange-500/50', shadow: 'shadow-[inset_4px_0_0_#f97316]' },
  medium:   { bg: 'bg-yellow-500/10', text: 'text-yellow-400', badge: 'bg-yellow-500/20 border-yellow-500/50', shadow: 'shadow-[inset_4px_0_0_#eab308]' },
  low:      { bg: 'bg-blue-500/10', text: 'text-blue-400', badge: 'bg-blue-500/20 border-blue-500/50', shadow: 'shadow-[inset_4px_0_0_#3b82f6]' },
};

export default function DetectionSplitEditor() {
  const { ruleText, isSimulating, hits, setRuleText, runSimulation } = useOmegaStore();

  const flatHits = useMemo(() => {
    return [...hits].sort((a, b) => b.ts - a.ts);
  }, [hits]);

  return (
    <div className="flex flex-col md:flex-row h-[600px] border border-indigo-500/30 rounded-xl overflow-hidden bg-[#060913] shadow-[0_0_40px_rgba(79,70,229,0.1)]">
      {/* Policy IDE */}
      <div className="w-full md:w-[40%] flex flex-col border-b md:border-b-0 md:border-r border-indigo-500/30 bg-[#03050a]">
        <div className="px-5 py-4 bg-indigo-950/20 border-b border-indigo-500/30 flex items-center justify-between">
          <div>
            <span className="text-xs uppercase tracking-widest font-mono text-indigo-300 font-bold">Detection Engineering IDE</span>
            <p className="text-[9px] font-mono text-indigo-500 mt-0.5">YARA / SIGMA / SNORT Universal Compiler</p>
          </div>
          <button
            onClick={runSimulation}
            disabled={isSimulating || !ruleText.trim()}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 text-white text-[10px] font-bold rounded uppercase tracking-widest transition-colors shadow-[0_0_15px_rgba(79,70,229,0.5)] disabled:shadow-none"
          >
            {isSimulating ? 'Compiling...' : 'Dry-Test Run ▶'}
          </button>
        </div>
        <textarea
          className="flex-1 p-5 bg-transparent text-emerald-400 font-mono text-sm leading-relaxed resize-none outline-none placeholder:text-slate-800"
          value={ruleText}
          onChange={(e) => setRuleText(e.target.value)}
          placeholder={`title: Universal Payload Drop\ndetection:\n  selection:\n    CommandLine|contains: '-EncodedCommand'\n  condition: selection\nlevel: high\n\n# Paste logic to evaluate...`}
          spellCheck={false}
        />
      </div>

      {/* Grid Hits View */}
      <div className="flex-1 flex flex-col bg-[#0a0f1c] relative">
        <div className="px-5 py-4 bg-indigo-950/20 border-b border-indigo-500/30 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full ${isSimulating ? 'bg-indigo-400 animate-pulse' : 'bg-emerald-400'} shadow-[0_0_10px_currentColor]`} />
            <span className="text-xs uppercase tracking-widest font-mono text-indigo-300 font-bold">Telemetry Hits Engine</span>
          </div>
          <div className="text-[10px] font-mono text-slate-400 bg-slate-900/50 px-3 py-1 rounded border border-slate-700">
            Total Matches: <strong className="text-white">{flatHits.length}</strong>
          </div>
        </div>
        
        <div className="flex-1 overflow-auto">
          {flatHits.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center gap-4 py-16 text-center">
              <div className="w-16 h-16 rounded-full border border-slate-800 flex items-center justify-center text-3xl opacity-20 bg-slate-900">🛡</div>
              <p className="text-xs text-slate-500 font-mono uppercase tracking-widest">Zero Detections Triggered</p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-[#0a0f1c] z-10 shadow-md">
                <tr className="border-b border-indigo-500/20 text-[9px] uppercase tracking-widest font-mono text-indigo-400">
                  <th className="py-3 px-4 w-24">Severity</th>
                  <th className="py-3 px-4 w-32">Source IP</th>
                  <th className="py-3 px-4">Context / Command Line</th>
                  <th className="py-3 px-4 w-32 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {flatHits.map((hit) => {
                  const style = SEV_STYLES[hit.severity];
                  return (
                    <tr key={hit.id} className={`border-b border-slate-800 hover:bg-slate-800/40 transition-colors ${style.shadow} ${style.bg}`}>
                      <td className="py-3 px-4">
                        <span className={`text-[9px] px-2 py-0.5 rounded border font-mono uppercase font-bold text-white ${style.badge}`}>
                          {hit.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="font-mono text-xs text-slate-200 font-bold">{hit.sourceIp || 'Unknown'}</span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-mono text-xs text-slate-400 break-all">{hit.context}</div>
                        <div className="text-[9px] text-slate-600 font-mono mt-1">{new Date(hit.ts).toISOString()}</div>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button className="px-3 py-1 bg-rose-600/20 hover:bg-rose-600/40 border border-rose-500/50 text-rose-400 rounded text-[9px] uppercase font-bold tracking-widest font-mono transition-colors">
                          Mitigate
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
