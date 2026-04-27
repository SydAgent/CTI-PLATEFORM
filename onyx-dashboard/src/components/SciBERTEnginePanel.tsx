"use client";

import { useState, useEffect, useRef } from 'react';
import { useOnyxStore } from '@/lib/store';

type Extraction = { raw?: string; rawText?: string; title?: string; text?: string; entities?: { label: string; text: string; conf?: number }[] };

export default function SciBERTEnginePanel() {
  const [stream, setStream] = useState<Extraction[]>([]);
  const [pinnedItems, setPinnedItems] = useState<Extraction[]>([]);
  const isPausedRef = useRef(false);
  const [isHovering, setIsHovering] = useState(false);

  const events = useOnyxStore(s => s.events);

  useEffect(() => {
    if (!isPausedRef.current) {
      // Filtrer les événements NLP depuis le flux SSE global, et les afficher (les plus récents en premier)
      const nlpData = [...events]
        .reverse()
        .filter(e => e.type === 'nlp_extraction')
        .map(e => e.data as Extraction)
        .slice(0, 15);
      
      if (nlpData.length > 0) {
        setStream(nlpData);
      }
    }
  }, [events]);

  const getRawString = (item: Extraction) => item.raw || item.rawText || item.title || item.text || '';

  const togglePin = (item: Extraction) => {
    setPinnedItems(prev => {
      if (prev.some(p => getRawString(p) === getRawString(item))) {
        return prev.filter(p => getRawString(p) !== getRawString(item));
      }
      return [item, ...prev].slice(0, 5); // Max 5 pinned items
    });
  };

  const renderHighlightedText = (item: Extraction) => {
    let tempRaw = getRawString(item);
    const chunks: React.ReactNode[] = [];
    let lastIndex = 0;
    
    const sortedEntities = [...(item.entities || [])].sort((a: any, b: any) => tempRaw.indexOf(a.text) - tempRaw.indexOf(b.text));

    sortedEntities.forEach((ent, idx) => {
      const matchIdx = tempRaw.indexOf(ent.text, lastIndex);
      if (matchIdx !== -1) {
        if (matchIdx > lastIndex) {
          chunks.push(<span key={`text-${idx}`} className="text-gray-300">{tempRaw.slice(lastIndex, matchIdx)}</span>);
        }
        
        let colorTheme = "border-cyan-500 bg-cyan-900/30 text-cyan-300";
        if (ent.label === 'THREAT_ACTOR') colorTheme = "border-red-500 bg-red-900/30 text-red-300";
        if (ent.label === 'IP_ADDRESS' || ent.label === 'DOMAIN') colorTheme = "border-green-500 bg-green-900/30 text-green-300";
        if (ent.label === 'MALWARE' || ent.label === 'HASH') colorTheme = "border-purple-500 bg-purple-900/30 text-purple-300";
        if (ent.label === 'MITRE_TTP') colorTheme = "border-amber-500 bg-amber-900/30 text-amber-300";

        chunks.push(
          <div key={`ent-${idx}`} className={`inline-flex items-center gap-1 mx-1 px-1.5 py-0.5 border ${colorTheme} rounded cursor-pointer relative group transition-colors duration-200 hover:bg-opacity-80`}>
            <span className="font-bold">{ent.text}</span>
            <span className="text-[9px] uppercase tracking-wider opacity-80 border-l border-current pl-1 ml-1">{ent.label}</span>
            <span className="absolute -top-6 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 transition-opacity bg-black border border-gray-700 text-white text-[10px] px-2 py-1 rounded whitespace-nowrap z-10 font-mono shadow-xl">
              Conf: {((ent.conf || 0) * 100).toFixed(1)}%
            </span>
          </div>
        );
        lastIndex = matchIdx + ent.text.length;
      }
    });

    if (lastIndex < tempRaw.length) {
      chunks.push(<span key="text-last" className="text-gray-300">{tempRaw.slice(lastIndex)}</span>);
    }
    
    return chunks.length > 0 ? chunks : <span className="text-gray-300">{tempRaw}</span>;
  };

  const renderStreamItem = (item: Extraction, idx: number, isPinned: boolean = false) => {
    const isAlreadyPinned = pinnedItems.some(p => getRawString(p) === getRawString(item));
    return (
      <div 
        key={isPinned ? `pinned-${idx}` : `stream-${idx}`} 
        style={!isPinned ? { animation: 'nlpSlideIn 0.4s ease-out' } : {}} 
        className={`relative group border-l-[3px] border-purple-500 bg-[#0a0f18]/80 p-4 rounded-r shadow-lg backdrop-blur-sm transition-all hover:bg-[#0c121e] ${isPinned ? 'border-amber-500 bg-[#120f0a]/90' : ''}`}
      >
        <button 
          onClick={() => togglePin(item)}
          className={`absolute top-2 right-2 p-1 rounded opacity-0 group-hover:opacity-100 transition-opacity text-[10px] uppercase font-bold border ${isAlreadyPinned ? 'bg-amber-900/50 text-amber-500 border-amber-500' : 'bg-gray-800 text-gray-400 border-gray-600 hover:text-white'}`}
        >
          {isAlreadyPinned ? '📌 RETIRER' : '📌 PIN'}
        </button>

        <div className="text-xs leading-relaxed tracking-wide pr-14">
          {renderHighlightedText(item)}
        </div>
        <div className="mt-3 flex flex-wrap gap-2 pt-2 border-t border-gray-800/50">
          {(item.entities || []).map((e, i) => (
            <div key={i} className="flex items-center gap-1.5 text-[10px] bg-black/40 px-2 py-1 rounded border border-gray-800">
              <span className="text-gray-400">{e.label}:</span>
              <span className="text-purple-300 font-semibold truncate max-w-[120px]">{e.text}</span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div 
      className="onyx-card animate-in h-[520px] bg-[#03060a] font-mono text-xs p-5 rounded-xl border border-purple-900/40 shadow-[0_0_40px_rgba(168,85,247,0.06)] overflow-hidden flex flex-col relative"
      onMouseEnter={() => { isPausedRef.current = true; setIsHovering(true); }}
      onMouseLeave={() => { isPausedRef.current = false; setIsHovering(false); }}
    >
      {/* Background Grid & Glow */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(168,85,247,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(168,85,247,0.05)_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none opacity-50"></div>
      <div className="absolute top-0 right-0 w-64 h-64 bg-purple-600/10 rounded-full blur-[80px] pointer-events-none"></div>

      <h3 className="text-purple-400 text-sm font-bold mb-4 flex items-center uppercase tracking-widest border-b border-purple-900/50 pb-3 relative z-10">
        <span className={`w-2 h-2 rounded-full ${isHovering ? 'bg-amber-500' : 'bg-purple-500 animate-[ping_1.5s_cubic-bezier(0,0,0.2,1)_infinite]'} mr-3 shadow-[0_0_10px_#a855f7]`}></span>
        Moteur de Reconnaissance SciBERT
        {isHovering && <span className="ml-3 text-[10px] text-amber-500 font-bold border border-amber-500/50 bg-amber-900/20 px-2 py-0.5 rounded">EN PAUSE</span>}
        <span className="ml-auto text-[10px] bg-purple-950 text-purple-300 px-2 py-1 rounded-full border border-purple-800 font-mono">RÉSEAU_NEURONAL_ACTIF</span>
      </h3>

      <div className="flex-1 overflow-y-auto space-y-4 pr-2 relative z-10 scrollbar-hide">
        {/* Pinned Items Section */}
        {pinnedItems.length > 0 && (
          <div className="space-y-4 mb-6 pb-6 border-b-2 border-dashed border-gray-800">
            <div className="text-[10px] text-gray-500 uppercase font-bold sticky top-0 bg-[#03060a]/90 backdrop-blur pb-2 z-20">📌 Renseignements Épinglés {isHovering ? ' — ' + pinnedItems.length + ' élément(s)' : ''}</div>
            {pinnedItems.map((item, idx) => renderStreamItem(item, idx, true))}
          </div>
        )}

        {/* Live Stream Section */}
        {stream.length === 0 && (
          <div className="flex flex-col items-center justify-center py-10 gap-5">
            {/* Neural Network Monitoring Visualization */}
            <div className="relative">
              <div className="w-20 h-20 rounded-full border-2 border-purple-500/30 flex items-center justify-center">
                <div className="w-14 h-14 rounded-full border border-purple-400/50 flex items-center justify-center animate-[spin_8s_linear_infinite]">
                  <div className="w-8 h-8 rounded-full bg-purple-500/20 border border-purple-400 flex items-center justify-center shadow-[0_0_20px_rgba(168,85,247,0.3)]">
                    <span className="text-purple-300 text-sm">◈</span>
                  </div>
                </div>
              </div>
              <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-green-500 animate-pulse shadow-[0_0_8px_#22c55e]" />
            </div>

            <div className="text-center space-y-1.5">
              <div className="text-[11px] text-purple-300 font-bold uppercase tracking-[0.2em]">Monitoring Actif</div>
              <div className="text-[10px] text-gray-500 leading-relaxed max-w-[260px]">
                Le réseau neuronal SciBERT analyse le flux SSE en temps réel.<br />
                Les extractions apparaîtront ici automatiquement.
              </div>
            </div>

            {/* Pipeline Status Indicators */}
            <div className="flex gap-3 mt-2">
              {[
                { label: 'SSE', status: true },
                { label: 'NLP', status: true },
                { label: 'NER', status: true },
              ].map(p => (
                <div key={p.label} className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-wider px-2.5 py-1 rounded border border-gray-800 bg-black/40">
                  <span className={`w-1.5 h-1.5 rounded-full ${p.status ? 'bg-green-500 shadow-[0_0_4px_#22c55e]' : 'bg-red-500'}`} />
                  <span className="text-gray-400">{p.label}</span>
                </div>
              ))}
            </div>

            <div className="flex items-center gap-2 mt-1">
              <div className="w-1 h-1 rounded-full bg-purple-500 animate-ping" />
              <span className="text-[9px] text-purple-600 uppercase tracking-[0.15em]">En attente du prochain signal OSINT</span>
            </div>
          </div>
        )}

        {stream.map((item, idx) => {
          // If already pinned, optionally hide from stream, but user asked to be able to "gelé un événement", so we can show it or let the pinned block handle it.
          if (pinnedItems.some(p => getRawString(p) === getRawString(item))) return null;
          return renderStreamItem(item, idx);
        })}

        <style dangerouslySetInnerHTML={{__html: `
          @keyframes nlpSlideIn { from { opacity: 0; transform: translateY(-10px) scale(0.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
          .scrollbar-hide::-webkit-scrollbar { display: none; }
          .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
        `}} />
      </div>
    </div>
  );
}
