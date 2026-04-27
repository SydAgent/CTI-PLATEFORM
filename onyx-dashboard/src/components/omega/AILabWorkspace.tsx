"use client";
import React, { useState, useEffect } from 'react';
import { useOmegaStore, TTPObservation } from '../../lib/store/omegaStore';

function MutationConsole({ active }: { active: boolean }) {
  const [logs, setLogs] = useState<string[]>([]);
  useEffect(() => {
    if(!active) return;
    const msgs = [
      "Optimizing adversarial weights...",
      "Injecting polymorphic payload signature...",
      "Bypassing static heuristic scans...",
      "Compiling evasion sandbox environment...",
      "Generating adversary emulation profile...",
    ];
    const id = setInterval(() => {
      setLogs(prev => [...prev.slice(-4), `[${new Date().toISOString().split('T')[1].slice(0,-1)}] ${msgs[Math.floor(Math.random() * msgs.length)]}`]);
    }, 2000);
    return () => clearInterval(id);
  }, [active]);

  return (
    <div className="bg-black border border-indigo-500/30 rounded p-3 h-32 flex flex-col justify-end font-mono text-[9px] text-indigo-400 shadow-[inset_0_0_20px_rgba(0,0,0,1)] overflow-hidden">
      {logs.map((l, i) => <div key={i} className="opacity-80">{l}</div>)}
      <div className="animate-pulse mt-1">&gt; ML_GENERATOR_ACTIVE _</div>
    </div>
  );
}

function ActiveScenarioCard({ ttp }: { ttp: TTPObservation }) {
  return (
    <div className="group relative border border-indigo-500/20 bg-indigo-950/10 rounded-lg p-4 hover:bg-indigo-900/30 hover:border-indigo-500/50 transition-all duration-300 overflow-hidden">
      <div className="absolute top-0 left-0 w-1 h-full bg-indigo-500 group-hover:shadow-[0_0_15px_#6366f1]" />
      <div className="flex justify-between items-start mb-2">
        <div>
          <span className="text-[10px] font-mono text-indigo-300 bg-indigo-500/20 px-2 py-0.5 rounded border border-indigo-500/30">{ttp.id}</span>
          <h3 className="text-sm font-bold text-slate-200 mt-2 font-mono tracking-tight">{ttp.name}</h3>
        </div>
        <div className="text-[10px] text-indigo-400 font-mono border border-indigo-500/30 rounded px-2 py-1 bg-black/40">
          GEN_CONF: {(ttp.confidence * 100).toFixed(0)}%
        </div>
      </div>
      <div className="flex items-center gap-2 mt-4 flex-wrap">
        <span className="text-[9px] uppercase tracking-widest font-mono text-slate-400 border border-slate-700 bg-slate-900 px-2 py-1 rounded">
          {ttp.tactic || 'MUTATING'}
        </span>
        <span className="text-[9px] text-slate-500 font-mono ml-auto">
          EPOCH: {Date.now().toString().slice(-6)}
        </span>
      </div>
    </div>
  );
}

export default function AILabWorkspace() {
  const { recentTTPs } = useOmegaStore();
  const isEmpty = recentTTPs.length === 0;

  return (
    <div className="bg-[#05070e] border border-purple-500/20 rounded-xl shadow-[0_0_40px_rgba(168,85,247,0.05)] flex flex-col h-[600px]">
      <div className="px-6 py-4 border-b border-purple-500/20 bg-[#080b14] flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="relative w-3 h-3">
            <div className={`absolute inset-0 rounded-sm ${!isEmpty ? 'bg-purple-500 animate-spin' : 'bg-slate-600'}`} style={{ animationDuration: '3s' }} />
            <div className={`absolute inset-0 rounded-sm ${!isEmpty ? 'bg-purple-400 animate-ping opacity-50' : ''}`} />
          </div>
          <div>
            <h2 className="text-sm font-black text-purple-50 uppercase tracking-[0.2em] font-mono">ML Deception Lab</h2>
            <p className="text-[10px] text-purple-400/70 uppercase tracking-widest font-mono mt-0.5">Adversarial Emulation Environment</p>
          </div>
        </div>
        {!isEmpty && (
          <div className="text-[10px] font-mono text-purple-300 border border-purple-500/40 bg-purple-500/10 px-3 py-1 rounded uppercase">
            {recentTTPs.length} Models Training
          </div>
        )}
      </div>

      <div className="flex-1 p-6 overflow-hidden flex flex-col gap-6">
        {isEmpty ? (
           <div className="flex-1 border border-dashed border-purple-500/20 rounded-xl flex flex-col items-center justify-center gap-4 bg-[radial-gradient(ellipse_at_center,_rgba(168,85,247,0.05)_0%,_transparent_70%)]">
             <div className="text-4xl opacity-40 animate-pulse text-purple-500">⚛</div>
             <p className="text-xs font-mono text-slate-400 max-w-sm text-center uppercase tracking-widest leading-relaxed">
               Lab Idle. Send telemetry through SciBERT pipeline to initialize adversarial mutation generation.
             </p>
           </div>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="md:col-span-1 flex flex-col gap-2">
                <p className="text-[10px] uppercase tracking-widest font-mono text-purple-500 font-bold">Training Console</p>
                <MutationConsole active={true} />
              </div>
              <div className="md:col-span-2 flex flex-col gap-2">
                <div className="flex justify-between items-end">
                  <p className="text-[10px] uppercase tracking-widest font-mono text-purple-500 font-bold">Active Emulations</p>
                  <p className="text-[9px] font-mono text-slate-500">Auto-deploying counter-measures</p>
                </div>
                <div className="grid grid-cols-2 gap-3 overflow-auto max-h-[400px] pr-2 custom-scrollbar">
                  {recentTTPs.map((ttp) => <ActiveScenarioCard key={`${ttp.id}-${ttp.ts}`} ttp={ttp} />)}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
