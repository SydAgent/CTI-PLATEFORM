"use client";
import React from 'react';
import { useOmegaStore, ActorProfile } from '../../lib/store/omegaStore';

function getRiskUI(score: number) {
  if (score >= 8.5) return { color: 'text-rose-400', border: 'border-rose-500/40', bg: 'bg-rose-500/10', glow: 'shadow-[0_0_30px_rgba(244,63,94,0.15)]' };
  if (score >= 6)   return { color: 'text-orange-400', border: 'border-orange-500/40', bg: 'bg-orange-500/10', glow: 'shadow-[0_0_20px_rgba(249,115,22,0.1)]' };
  return { color: 'text-yellow-400', border: 'border-yellow-500/40', bg: 'bg-yellow-500/10', glow: '' };
}

function HighDensityActorCard({ actor }: { actor: ActorProfile }) {
  const ui = getRiskUI(actor.riskScore);
  
  return (
    <div className={`flex flex-col bg-[#070b14] border ${ui.border} rounded-xl overflow-hidden hover:scale-[1.02] transition-transform duration-300 ${ui.glow} group cursor-crosshair`}>
      <div className={`px-4 py-3 border-b border-slate-800 ${ui.bg} flex justify-between items-start`}>
        <div>
          <h3 className={`text-lg font-black font-mono tracking-tight uppercase ${ui.color}`}>{actor.name}</h3>
          <p className="text-[9px] font-mono text-slate-400 uppercase tracking-widest mt-1">{actor.category} · {actor.sector}</p>
        </div>
        <div className="flex flex-col items-end">
          <span className={`text-2xl font-black font-mono leading-none ${ui.color}`}>{actor.riskScore.toFixed(1)}</span>
          <span className="text-[8px] uppercase tracking-widest font-mono text-slate-500 mt-1">Risk Index</span>
        </div>
      </div>
      
      <div className="p-4 flex-1 flex flex-col gap-4">
        <div>
          <p className="text-[9px] uppercase tracking-widest font-mono text-slate-600 mb-1 font-bold">Business Impact</p>
          <p className="text-xs text-slate-300 leading-relaxed line-clamp-3">{actor.businessImpact}</p>
        </div>
        
        <div className="mt-auto">
          <p className="text-[9px] uppercase tracking-widest font-mono text-slate-600 mb-2 font-bold">TTP Signatures</p>
          <div className="flex flex-wrap gap-1.5">
            {actor.ttps.slice(0,4).map(t => (
              <span key={t} className="px-2 py-0.5 border border-slate-700 bg-slate-900 rounded text-[9px] font-mono text-slate-400 group-hover:border-indigo-500/50 group-hover:text-indigo-300 transition-colors">
                {t}
              </span>
            ))}
            {actor.ttps.length > 4 && <span className="px-2 py-0.5 text-[9px] font-mono text-slate-500">+{actor.ttps.length - 4}</span>}
          </div>
        </div>
      </div>
      
      <div className="px-4 py-2 bg-black/40 border-t border-slate-800 flex justify-between items-center opacity-60 group-hover:opacity-100 transition-opacity">
         <span className="text-[9px] font-mono text-slate-500">Last Intel: {new Date(actor.lastSeen).toLocaleDateString()}</span>
         <span className="text-[9px] font-mono text-indigo-400 font-bold uppercase tracking-widest">Deep Dive ↗</span>
      </div>
    </div>
  );
}

export default function ActorProfileCard() {
  const { threatActors } = useOmegaStore();

  return (
    <div className="bg-[#04060c] border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col">
      <div className="px-6 py-5 border-b border-slate-800 bg-gradient-to-r from-slate-900 to-transparent flex items-center justify-between">
        <div>
          <h2 className="text-sm font-black text-slate-100 uppercase tracking-[0.2em] font-mono">Threat Actor Intelligence</h2>
          <p className="text-[10px] text-slate-500 uppercase tracking-widest font-mono mt-1">Attributed Adversary Profiles</p>
        </div>
        {threatActors.length > 0 && (
          <div className="px-4 py-1.5 border border-rose-500/30 bg-rose-500/10 rounded">
             <span className="text-xs font-mono font-bold text-rose-400 tracking-widest">{threatActors.length} Tracked</span>
          </div>
        )}
      </div>

      <div className="p-6 overflow-auto custom-scrollbar">
        {threatActors.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-4 py-20 text-center border border-dashed border-slate-800 rounded-xl">
             <span className="text-5xl opacity-20 filter grayscale">👤</span>
             <p className="text-xs text-slate-500 font-mono uppercase tracking-widest">Database Empty. No attributed actors.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {threatActors.map(actor => <HighDensityActorCard key={actor.id} actor={actor} />)}
          </div>
        )}
      </div>
    </div>
  );
}
