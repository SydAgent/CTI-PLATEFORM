"use client";
import React, { useEffect, useState } from 'react';
import { useOmegaStore, Severity } from '../../lib/store/omegaStore';

const SEV_CONFIG: Record<Severity, { label: string; color: string; hex: string; bg: string }> = {
  critical: { label: 'CRITICAL', color: 'text-rose-400', hex: '#f43f5e', bg: 'bg-rose-500' },
  high:     { label: 'HIGH',     color: 'text-orange-400', hex: '#f97316', bg: 'bg-orange-500' },
  medium:   { label: 'MEDIUM',   color: 'text-yellow-400', hex: '#eab308', bg: 'bg-yellow-500' },
  low:      { label: 'LOW',      color: 'text-blue-400', hex: '#3b82f6', bg: 'bg-blue-500' },
};

function LiveWaterFall({ active }: { active: boolean }) {
  const [bars, setBars] = useState<number[]>(Array(40).fill(0));
  useEffect(() => {
    if(!active) return;
    const id = setInterval(() => {
      setBars(prev => [...prev.slice(1), Math.random() * 100]);
    }, 150);
    return () => clearInterval(id);
  }, [active]);

  return (
    <div className="flex items-end gap-1 h-12 w-full overflow-hidden opacity-40">
      {bars.map((h, i) => (
        <div key={i} className="flex-1 bg-emerald-500 rounded-t-sm transition-all duration-150" style={{ height: `${h}%` }} />
      ))}
    </div>
  );
}

export default function TelemetryDashboard() {
  const { severityDistribution: dist } = useOmegaStore();
  const { critical, high, medium, low, total, lastSyncTs } = dist;
  const hasData = total > 0;
  
  const [age, setAge] = useState(0);
  useEffect(() => {
    const i = setInterval(() => setAge(Math.floor((Date.now() - lastSyncTs)/1000)), 1000);
    return () => clearInterval(i);
  }, [lastSyncTs]);

  const globalScore = hasData ? ((critical * 10 + high * 7 + medium * 4 + low * 1) / total).toFixed(2) : '0.00';

  return (
    <div className="bg-[#040914] border border-emerald-500/20 rounded-xl p-6 shadow-[0_0_50px_rgba(16,185,129,0.05)] flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-emerald-500/20 pb-4">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="w-3 h-3 rounded-full bg-emerald-400 shadow-[0_0_15px_#34d399] z-10 relative" />
            <div className="w-3 h-3 rounded-full bg-emerald-400 animate-ping absolute inset-0" />
          </div>
          <div>
            <h2 className="text-sm font-black text-emerald-50 uppercase tracking-[0.2em] font-mono">eBPF Telemetry Stream</h2>
            <p className="text-[10px] text-emerald-500/70 font-mono uppercase tracking-widest mt-0.5">Continuous Threat Exposure Management</p>
          </div>
        </div>
        <div className="flex flex-col items-end">
          <span className="text-[10px] font-mono text-emerald-400 border border-emerald-400/30 px-2 py-0.5 rounded bg-emerald-500/10 uppercase">
            Sync: {age < 5 ? 'Live' : `${age}s`}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Global Score Panel */}
        <div className="md:col-span-1 bg-gradient-to-br from-emerald-950/40 to-[#040914] border border-emerald-500/30 rounded-xl p-6 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10">
            <svg width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-emerald-500"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-widest text-emerald-500 font-mono font-bold">Global Risk Index</p>
            <div className="text-5xl font-mono font-black text-emerald-400 mt-2 tracking-tighter drop-shadow-[0_0_10px_rgba(52,211,153,0.5)]">
              {globalScore}
            </div>
            <p className="text-[10px] text-emerald-500/60 font-mono mt-1">Weighted severity coefficient</p>
          </div>
          <div className="mt-6">
            <LiveWaterFall active={hasData} />
          </div>
        </div>

        {/* Dense Severity Distribution */}
        <div className="md:col-span-2 bg-[#060b18] border border-slate-800 rounded-xl p-6 flex flex-col">
          <div className="flex justify-between items-center mb-6">
            <span className="text-[10px] uppercase tracking-widest font-mono text-slate-500 font-bold">Severity Topography</span>
            <span className="text-xs font-mono font-bold text-white bg-slate-800 px-3 py-1 rounded-full">{total} Events Processed</span>
          </div>
          
          <div className="flex-1 flex flex-col justify-center gap-4">
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => {
              const val = dist[sev];
              const cfg = SEV_CONFIG[sev];
              const pct = total > 0 ? (val / total) * 100 : 0;
              return (
                <div key={sev} className="flex items-center gap-4 group">
                  <span className={`w-20 text-[10px] font-mono font-bold tracking-widest uppercase text-right ${cfg.color}`}>
                    {cfg.label}
                  </span>
                  <div className="flex-1 h-3 bg-slate-900 rounded-full overflow-hidden relative border border-slate-800">
                    <div 
                      className={`h-full rounded-full transition-all duration-700 ease-out ${cfg.bg} shadow-[0_0_10px_${cfg.hex}] group-hover:brightness-125`}
                      style={{ width: `${pct}%` }} 
                    />
                  </div>
                  <span className={`w-12 text-xs font-mono font-bold text-right ${cfg.color}`}>{val}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
