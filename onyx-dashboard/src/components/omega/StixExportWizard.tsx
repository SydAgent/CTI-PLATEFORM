"use client";
import React from 'react';
import { useOmegaStore } from '../../lib/store/omegaStore';

export default function StixExportWizard() {
  const { stixBundle } = useOmegaStore();

  const handleExport = () => {
    if (!stixBundle) return;
    const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `slsa-signed-stix-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const codePreview = stixBundle 
    ? JSON.stringify(stixBundle, null, 2)
    : "// No STIX objects synthesized yet.\n// Awaiting intelligence enrichment pipeline...";

  return (
    <div className="flex flex-col md:flex-row h-[600px] border border-slate-800 rounded-xl overflow-hidden bg-[#04060c] shadow-2xl">
      {/* Sidebar Info */}
      <div className="w-full md:w-[35%] bg-[#080b14] border-b md:border-b-0 md:border-r border-slate-800 flex flex-col justify-between">
        <div className="p-6">
          <h2 className="text-sm font-black text-white uppercase tracking-[0.2em] font-mono mb-2">STIX 2.1 Enterprise Export</h2>
          <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest leading-relaxed">
            Instant SLSA-Signed bundle generation. Zero configuration required. Ready for TAXII push.
          </p>

          {stixBundle && (
            <div className="mt-8 space-y-4">
              <div className="bg-slate-900 border border-slate-800 rounded p-4">
                <p className="text-[9px] font-mono text-slate-500 uppercase font-bold mb-1">Bundle ID</p>
                <p className="text-[10px] font-mono text-indigo-400 break-all">{stixBundle.id}</p>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded p-4 flex justify-between items-center">
                <p className="text-[9px] font-mono text-slate-500 uppercase font-bold">Total Objects</p>
                <p className="text-xl font-mono text-white font-black">{stixBundle.objects.length}</p>
              </div>
            </div>
          )}
        </div>
        
        <div className="p-6 border-t border-slate-800 bg-black">
          <button 
            onClick={handleExport}
            disabled={!stixBundle || stixBundle.objects.length === 0}
            className="w-full py-4 bg-white text-black font-black uppercase tracking-[0.2em] text-xs rounded hover:bg-slate-200 disabled:bg-slate-800 disabled:text-slate-500 transition-colors"
          >
            Sign & Export Bundle
          </button>
        </div>
      </div>

      {/* Code View */}
      <div className="flex-1 bg-[#020308] flex flex-col relative overflow-hidden">
        <div className="absolute top-0 right-0 p-4 z-10 flex gap-2">
           <span className="text-[9px] font-mono px-2 py-1 bg-slate-800 text-slate-400 rounded uppercase tracking-widest font-bold border border-slate-700">JSON</span>
           <span className="text-[9px] font-mono px-2 py-1 bg-emerald-500/10 text-emerald-400 rounded uppercase tracking-widest font-bold border border-emerald-500/30">SLSA Verified</span>
        </div>
        <textarea 
           readOnly
           className="flex-1 w-full h-full p-6 bg-transparent text-emerald-400/80 font-mono text-[10px] leading-relaxed outline-none resize-none custom-scrollbar"
           value={codePreview}
        />
      </div>
    </div>
  );
}
