"use client";

import { useState, useEffect } from 'react';

type Extraction = { raw: string; entities: { label: string; text: string; conf: number }[] };

export default function SciBERTEnginePanel() {
  const [stream, setStream] = useState<Extraction[]>([]);

  useEffect(() => {
    let ws: WebSocket;
    const connect = () => {
      ws = new WebSocket('ws://localhost:8000/ws/nlp');
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setStream(prev => [data, ...prev].slice(0, 15));
        } catch (e) {}
      };
      ws.onclose = () => setTimeout(connect, 3000);
    };
    connect();
    return () => ws?.close();
  }, []);

  // Spectaculaire text highlighting function (Cortex/TRAM style)
  const renderHighlightedText = (item: Extraction) => {
    let tempRaw = item.raw;
    const chunks: React.ReactNode[] = [];
    let lastIndex = 0;
    
    // Sort entities by appearance in text to prevent overlap issues
    const sortedEntities = [...item.entities].sort((a, b) => tempRaw.indexOf(a.text) - tempRaw.indexOf(b.text));

    sortedEntities.forEach((ent, idx) => {
      const matchIdx = tempRaw.indexOf(ent.text, lastIndex);
      if (matchIdx !== -1) {
        // Push preceding raw text
        if (matchIdx > lastIndex) {
          chunks.push(<span key={`text-${idx}`} className="text-gray-300">{tempRaw.slice(lastIndex, matchIdx)}</span>);
        }
        
        // Pick dynamic color based on entity type
        let colorTheme = "border-cyan-500 bg-cyan-900/30 text-cyan-300";
        if (ent.label === 'THREAT_ACTOR') colorTheme = "border-red-500 bg-red-900/30 text-red-300";
        if (ent.label === 'IP_ADDRESS' || ent.label === 'DOMAIN') colorTheme = "border-green-500 bg-green-900/30 text-green-300";
        if (ent.label === 'MALWARE' || ent.label === 'HASH') colorTheme = "border-purple-500 bg-purple-900/30 text-purple-300";
        if (ent.label === 'MITRE_TTP') colorTheme = "border-amber-500 bg-amber-900/30 text-amber-300";

        // Push highlighted entity
        chunks.push(
          <div key={`ent-${idx}`} className={`inline-flex items-center gap-1 mx-1 px-1.5 py-0.5 border ${colorTheme} rounded cursor-pointer relative group transition-colors duration-200 hover:bg-opacity-80`}>
            <span className="font-bold">{ent.text}</span>
            <span className="text-[9px] uppercase tracking-wider opacity-80 border-l border-current pl-1 ml-1">{ent.label}</span>
            <span className="absolute -top-6 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 transition-opacity bg-black border border-gray-700 text-white text-[10px] px-2 py-1 rounded whitespace-nowrap z-10 font-mono shadow-xl">
              Conf: {(ent.conf * 100).toFixed(1)}%
            </span>
          </div>
        );
        lastIndex = matchIdx + ent.text.length;
      }
    });

    // Push remaining text
    if (lastIndex < tempRaw.length) {
      chunks.push(<span key="text-last" className="text-gray-300">{tempRaw.slice(lastIndex)}</span>);
    }
    
    return chunks.length > 0 ? chunks : <span className="text-gray-300">{item.raw}</span>;
  };

  return (
    <div className="onyx-card animate-in h-[480px] bg-[#03060a] font-mono text-xs p-5 rounded-xl border border-purple-900/40 shadow-[0_0_40px_rgba(168,85,247,0.06)] overflow-hidden flex flex-col relative">
      {/* Background Grid & Glow */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(168,85,247,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(168,85,247,0.05)_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none opacity-50"></div>
      <div className="absolute top-0 right-0 w-64 h-64 bg-purple-600/10 rounded-full blur-[80px] pointer-events-none"></div>

      <h3 className="text-purple-400 text-sm font-bold mb-4 flex items-center uppercase tracking-widest border-b border-purple-900/50 pb-3 relative z-10">
        <span className="w-2 h-2 rounded-full bg-purple-500 animate-[ping_1.5s_cubic-bezier(0,0,0.2,1)_infinite] mr-3 shadow-[0_0_10px_#a855f7]"></span>
        SciBERT Reconnaissance Engine
        <span className="ml-auto text-[10px] bg-purple-950 text-purple-300 px-2 py-1 rounded-full border border-purple-800 font-mono">NEURAL_NET_LIVE</span>
      </h3>

      <div className="flex-1 overflow-y-auto space-y-4 pr-2 relative z-10 scrollbar-hide">
        {stream.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-gray-500 opacity-60">
            <span className="text-2xl mb-2 animate-pulse">⚙️</span>
            <div>AWAITING NLP PIPELINE DATA...</div>
          </div>
        )}
        {stream.map((item, idx) => (
          <div key={idx} style={{ animation: 'nlpSlideIn 0.4s ease-out' }} className="border-l-[3px] border-purple-500 bg-[#0a0f18]/80 p-4 rounded-r shadow-lg backdrop-blur-sm transition-all hover:bg-[#0c121e]">
            <div className="text-xs leading-relaxed tracking-wide">
              {renderHighlightedText(item)}
            </div>
            {/* Entity badges footer */}
            <div className="mt-3 flex flex-wrap gap-2 pt-2 border-t border-gray-800/50">
              {item.entities.map((e, i) => (
                <div key={i} className="flex items-center gap-1.5 text-[10px] bg-black/40 px-2 py-1 rounded border border-gray-800">
                  <span className="text-gray-400">{e.label}:</span>
                  <span className="text-purple-300 font-semibold truncate max-w-[120px]">{e.text}</span>
                  <div className="w-8 flex bg-gray-900 h-1.5 rounded-full ml-1 overflow-hidden">
                     <div className="h-full bg-purple-500" style={{ width: `${e.conf * 100}%` }}></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
        <style dangerouslySetInnerHTML={{__html: `
          @keyframes nlpSlideIn { from { opacity: 0; transform: translateY(-10px) scale(0.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
          .scrollbar-hide::-webkit-scrollbar { display: none; }
          .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
        `}} />
      </div>
    </div>
  );
}
