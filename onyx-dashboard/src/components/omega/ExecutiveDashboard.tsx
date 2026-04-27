"use client";
import React from 'react';
import { useOmegaStore, Severity } from '../../lib/store/omegaStore';

const RISK_UI: Record<Severity, { bg: string; text: string; label: string; border: string }> = {
  critical: { bg: 'bg-rose-500', text: 'text-rose-500', label: 'CRITICAL', border: 'border-rose-500' },
  high:     { bg: 'bg-orange-500', text: 'text-orange-500', label: 'HIGH', border: 'border-orange-500' },
  medium:   { bg: 'bg-yellow-500', text: 'text-yellow-500', label: 'MEDIUM', border: 'border-yellow-500' },
  low:      { bg: 'bg-blue-500', text: 'text-blue-500', label: 'LOW', border: 'border-blue-500' },
};

export default function ExecutiveDashboard() {
  const { severityDistribution: dist, threatActors, lastGlobalSync } = useOmegaStore();
  const { critical, high, medium, low, total } = dist;
  const hasData = total > 0;
  
  const overallRisk: Severity = critical > 0 ? 'critical' : high > 0 ? 'high' : medium > 0 ? 'medium' : 'low';
  const ui = RISK_UI[overallRisk];

  if (!hasData) {
    return (
      <div className="bg-white border border-slate-200 rounded-xl p-12 text-center shadow-lg">
        <h2 className="text-3xl font-black text-slate-900 tracking-tight font-sans">CISO SYNTHESIS</h2>
        <p className="text-sm font-mono text-slate-500 mt-2 uppercase tracking-widest">Awaiting enterprise telemetry data.</p>
      </div>
    );
  }

  return (
    <div className="bg-white border border-slate-200 rounded-2xl shadow-xl overflow-hidden font-sans">
      <div className={`p-8 border-b-4 ${ui.border} bg-slate-50 flex flex-col md:flex-row justify-between items-start md:items-center gap-6`}>
        <div>
          <h1 className="text-4xl font-black text-slate-900 tracking-tighter">CISO SYNTHESIS</h1>
          <p className="text-xs font-mono text-slate-500 uppercase tracking-widest mt-2 font-bold">Board of Directors · Executive Summary · {new Date().toLocaleDateString()}</p>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-right">
             <p className="text-[10px] font-mono uppercase tracking-widest text-slate-500 font-bold mb-1">Global Risk Posture</p>
             <p className={`text-3xl font-black font-mono ${ui.text}`}>{ui.label}</p>
          </div>
        </div>
      </div>

      <div className="p-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-8">
          <div>
            <h3 className="text-xs font-mono uppercase tracking-widest font-black text-slate-900 mb-4 border-b border-slate-200 pb-2">Critical Action Directives</h3>
            <div className="space-y-3">
               {critical > 0 && (
                 <div className="flex items-start gap-4 p-4 bg-rose-50 border border-rose-100 rounded-lg">
                   <span className="text-xl">🚨</span>
                   <div>
                     <p className="font-bold text-slate-900">Immediate Remediation Required</p>
                     <p className="text-sm text-slate-600 mt-1">Contain {critical} critical events across the infrastructure. Imminent breach risk detected.</p>
                   </div>
                 </div>
               )}
               {threatActors.filter(a => a.riskScore >= 8.5).length > 0 && (
                 <div className="flex items-start gap-4 p-4 bg-orange-50 border border-orange-100 rounded-lg">
                   <span className="text-xl">⚠️</span>
                   <div>
                     <p className="font-bold text-slate-900">Nation-State Adversary Active</p>
                     <p className="text-sm text-slate-600 mt-1">High-risk threat actors observed in proximity to critical assets. Initiate Zero Trust locks.</p>
                   </div>
                 </div>
               )}
               {critical === 0 && (
                 <div className="flex items-start gap-4 p-4 bg-emerald-50 border border-emerald-100 rounded-lg">
                   <span className="text-xl">✅</span>
                   <div>
                     <p className="font-bold text-slate-900">Operations Normal</p>
                     <p className="text-sm text-slate-600 mt-1">No critical threats detected. Continue baseline CTEM monitoring.</p>
                   </div>
                 </div>
               )}
            </div>
          </div>
          
          <div className="grid grid-cols-2 gap-4">
             <div className="p-6 bg-slate-50 border border-slate-200 rounded-xl">
                <p className="text-[10px] font-mono uppercase tracking-widest font-bold text-slate-500 mb-2">Total Events Analysed</p>
                <p className="text-4xl font-black font-mono text-slate-900">{total.toLocaleString()}</p>
             </div>
             <div className="p-6 bg-slate-50 border border-slate-200 rounded-xl">
                <p className="text-[10px] font-mono uppercase tracking-widest font-bold text-slate-500 mb-2">Adversaries Tracked</p>
                <p className="text-4xl font-black font-mono text-slate-900">{threatActors.length}</p>
             </div>
          </div>
        </div>

        <div className="lg:col-span-1 bg-slate-900 rounded-xl p-6 text-white shadow-inner">
           <h3 className="text-xs font-mono uppercase tracking-widest font-black text-slate-400 mb-6 border-b border-slate-800 pb-2">Telemetry Breakdown</h3>
           <div className="space-y-6">
             <div className="flex justify-between items-center">
               <span className="font-mono text-sm text-rose-400 font-bold uppercase">Critical</span>
               <span className="font-mono text-2xl font-black">{critical}</span>
             </div>
             <div className="flex justify-between items-center">
               <span className="font-mono text-sm text-orange-400 font-bold uppercase">High</span>
               <span className="font-mono text-2xl font-black">{high}</span>
             </div>
             <div className="flex justify-between items-center">
               <span className="font-mono text-sm text-yellow-400 font-bold uppercase">Medium</span>
               <span className="font-mono text-2xl font-black">{medium}</span>
             </div>
             <div className="flex justify-between items-center">
               <span className="font-mono text-sm text-blue-400 font-bold uppercase">Low</span>
               <span className="font-mono text-2xl font-black">{low}</span>
             </div>
           </div>
           <div className="mt-8 pt-6 border-t border-slate-800">
             <p className="text-[9px] font-mono text-slate-500 uppercase tracking-widest text-center">Data synchronized via Omega Engine</p>
           </div>
        </div>
      </div>
    </div>
  );
}
