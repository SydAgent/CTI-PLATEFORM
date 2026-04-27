"use client";

import React, { useState, useEffect } from 'react';
import { Share2, Info, Target, AlertTriangle, ShieldAlert, Fingerprint } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface STIXObject {
  type: string;
  id: string;
  name?: string;
  value?: string;
  description?: string;
  confidence?: number;
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
  [key: string]: unknown;
}

interface STIXBundle {
  type: 'bundle';
  id: string;
  objects: STIXObject[];
}

export default function STIXBundleViewer({ tlp }: { tlp: string }) {
  const [stixData, setStixData] = useState<STIXBundle | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<STIXObject | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);

    const token = localStorage.getItem('onyx_access_token') || '';
    fetch(`${API}/api/v1/reports/export/stix?tlp=${tlp}`, {
      headers: { 'Authorization': `Bearer ${token}` },
      signal: controller.signal,
    })
      .then(res => {
        if (!res.ok) throw new Error(`Erreur serveur: ${res.status}`);
        return res.json() as Promise<STIXBundle>;
      })
      .then(data => { setStixData(data); })
      .catch((err: unknown) => {
        if (err instanceof Error && err.name !== 'AbortError') {
          setError(err.message);
        }
      })
      .finally(() => { setLoading(false); });

    return () => { controller.abort(); };
  }, [tlp]);

  if (loading) return <div className="text-gray-500 p-8 font-mono animate-pulse text-center border border-gray-800 rounded-lg">Synchronisation Ontologique...</div>;
  if (error) return <div className="text-red-500 p-4 text-xs font-mono border border-red-900 bg-red-900/10 rounded-lg">ERREUR CRITIQUE: {error}</div>;
  if (!stixData || !stixData.objects) return null;

  // Topological sorting
  const sdo = stixData.objects.filter((o: STIXObject) => !o?.type?.includes('rel') && !o?.type?.includes('-addr') && !o?.type?.includes('file') && o?.type !== 'report');
  const sco = stixData.objects.filter((o: STIXObject) => o?.type?.includes('-addr') || o?.type?.includes('file') || o?.type?.includes('domain'));
  const sro = stixData.objects.filter((o: STIXObject) => o?.type === 'relationship');

  const getNodeIcon = (type: string) => {
    if (type.includes('actor') || type.includes('intrusion')) return <ShieldAlert size={14} className="text-red-500" />;
    if (type.includes('indicator') || type.includes('malware')) return <AlertTriangle size={14} className="text-amber-500" />;
    if (type.includes('campaign')) return <Target size={14} className="text-purple-500" />;
    return <Fingerprint size={14} className="text-cyan-500" />;
  };

  return (
    <div className="mt-8 flex flex-col gap-4">
      <div className="bg-[#0a0f1a] border border-gray-800 rounded-xl overflow-hidden flex min-h-[450px]">
        
        {/* Left: Interactive Tree (Visual Mapping) */}
        <div className="flex-1 p-6 relative overflow-y-auto">
           <h3 className="text-base font-bold flex items-center gap-2 mb-6 text-white border-b border-gray-800 pb-3">
             <Share2 size={18} className="text-[#00eeff]" /> Explorateur de Relations STIX
           </h3>
           
           <div className="relative border-l-2 border-gray-800 ml-4 pl-6 space-y-8">
              {/* SDO Section */}
              <div className="relative">
                 <div className="absolute -left-[33px] bg-[#050505] border-2 border-amber-500 text-amber-500 rounded-full p-1 z-10"><Target size={14}/></div>
                 <h4 className="text-xs font-bold text-amber-500 uppercase tracking-widest mb-4">Campagnes & Acteurs (SDO)</h4>
                 <div className="grid grid-cols-2 gap-3">
                    {sdo.map((node: STIXObject) => (
                      <div 
                        key={node.id} 
                        onClick={() => setSelectedNode(node)}
                        className={`p-3 rounded-lg border transition-all cursor-pointer group ${selectedNode?.id === node.id ? 'bg-amber-500/10 border-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.15)]' : 'bg-[#0f172a] border-gray-700 hover:border-gray-500'}`}
                      >
                         <div className="flex items-center gap-2 mb-1">
                            {getNodeIcon(node.type)}
                            <span className="font-bold text-xs text-gray-200 capitalize group-hover:text-amber-400 transition-colors">{node.type.replace('-', ' ')}</span>
                         </div>
                         <div className="text-[11px] text-gray-400 font-mono truncate" title={node.name}>{node.name || node.id}</div>
                      </div>
                    ))}
                 </div>
              </div>

              {/* SCO Section */}
              <div className="relative">
                 <div className="absolute -left-[33px] bg-[#050505] border-2 border-cyan-500 text-cyan-500 rounded-full p-1 z-10"><Fingerprint size={14}/></div>
                 <h4 className="text-xs font-bold text-cyan-500 uppercase tracking-widest mb-4">Cyber Observables (SCO)</h4>
                 <div className="flex flex-wrap gap-2">
                    {sco.map((node: STIXObject) => {
                      const sros = sro.filter((r: STIXObject) => r.source_ref === node.id || r.target_ref === node.id);
                      return (
                      <div 
                        key={node.id} 
                        onClick={() => setSelectedNode(node)}
                        className={`px-3 py-2 rounded border flex items-center gap-2 cursor-pointer transition-all ${selectedNode?.id === node.id ? 'bg-cyan-900/30 border-cyan-500 text-cyan-400 shadow-[0_0_10px_rgba(0,238,255,0.2)]' : 'bg-black/40 border-gray-800 text-gray-400 hover:border-gray-600'}`}
                        title={sros.length > 0 ? `Lié par ${sros[0].relationship_type}` : ''}
                      >
                         <div className="w-1.5 h-1.5 rounded-full bg-cyan-500/50"></div>
                         <span className="text-[10px] font-mono">{node.value || node.name || node.type}</span>
                      </div>
                    )})}
                 </div>
              </div>
           </div>
        </div>

        {/* Right: Dynamic Narrative Panel */}
        <div className="w-80 border-l border-gray-800 bg-[#050505] p-6 flex flex-col">
           <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-4 flex items-center gap-2"><Info size={14}/> Explication Dynamique</h3>
           
           {selectedNode ? (
             <div className="animate-in slide-in-from-right-4 duration-300">
               <div className="flex items-start gap-3 mb-4">
                 <div className="p-2 bg-white/5 rounded-lg border border-gray-800">{getNodeIcon(selectedNode.type)}</div>
                 <div>
                   <div className="text-xs text-gray-500 uppercase font-bold tracking-widest">{selectedNode.type}</div>
                   <div className="text-sm font-bold text-white break-words">{selectedNode.name || selectedNode.value || 'Objet Restreint'}</div>
                 </div>
               </div>
               
               <div className="space-y-4">
                 {selectedNode.description && (
                   <div>
                     <div className="text-[10px] text-gray-500 font-mono mb-1">DESCRIPTION TACTIQUE</div>
                     <p className="text-xs text-gray-300 leading-relaxed bg-[#0a0f1a] p-3 rounded border border-gray-800">{selectedNode.description}</p>
                   </div>
                 )}
                 
                 {/* Auto-narrative based on relations */}
                 <div>
                    <div className="text-[10px] text-gray-500 font-mono mb-1">MÉCANIQUE RELATIONNELLE</div>
                    <div className="flex flex-col gap-2">
                      {sro.filter((r: STIXObject) => r.source_ref === selectedNode.id).map((r: STIXObject, idx: number) => {
                         const target = stixData.objects.find((o: STIXObject) => o.id === r.target_ref);
                         const relLabel = (r.relationship_type ?? 'related-to').replace(/-/g, ' ');
                         return target ? (
                           <div key={idx} className="text-[11px] p-2 bg-indigo-500/10 border border-indigo-500/20 rounded text-indigo-200">
                              <strong className="text-white">Ce composant</strong> {relLabel} <strong className="text-white capitalize">{target.type}</strong> ({target.name ?? target.value})
                           </div>
                         ) : null;
                      })}
                      {sro.filter((r: STIXObject) => r.target_ref === selectedNode.id).map((r: STIXObject, idx: number) => {
                         const source = stixData.objects.find((o: STIXObject) => o.id === r.source_ref);
                         const relLabel = (r.relationship_type ?? 'related-to').replace(/-/g, ' ');
                         return source ? (
                           <div key={idx} className="text-[11px] p-2 bg-teal-500/10 border border-teal-500/20 rounded text-teal-200">
                              <strong className="text-white capitalize">{source.type}</strong> ({source.name ?? source.value}) {relLabel} <strong className="text-white">ce composant</strong>
                           </div>
                         ) : null;
                      })}
                      {sro.filter((r: STIXObject) => r.source_ref === selectedNode.id || r.target_ref === selectedNode.id).length === 0 && (
                        <div className="text-[10px] text-gray-600 font-mono italic">Aucune relation transitive isolée. Objet terminal.</div>
                      )}
                    </div>
                 </div>

                 {/* Confidence or metadata */}
                 {selectedNode.confidence && (
                    <div className="flex items-center gap-2 mt-4 pt-4 border-t border-gray-800">
                      <div className="text-[10px] text-gray-500 font-mono">FIABILITÉ ML</div>
                      <div className="w-full h-1.5 bg-gray-900 rounded-full overflow-hidden flex-1">
                        <div className="h-full bg-green-500" style={{ width: `${selectedNode.confidence}%` }}></div>
                      </div>
                      <div className="text-[10px] text-green-500 font-mono font-bold">{selectedNode.confidence}%</div>
                    </div>
                 )}
               </div>
             </div>
           ) : (
             <div className="flex-1 flex flex-col items-center justify-center text-center opacity-50">
               <Share2 size={32} className="mb-3 text-gray-600" />
               <p className="text-xs text-gray-400 font-mono">Sélectionnez un composant de la Kill Chain pour générer le narratif de menace.</p>
             </div>
           )}
        </div>
        
      </div>
    </div>
  );
}
