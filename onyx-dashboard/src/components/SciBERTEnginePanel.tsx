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
          setStream(prev => [data, ...prev].slice(0, 10));
        } catch (e) {}
      };
      ws.onclose = () => setTimeout(connect, 2000);
    };
    connect();
    return () => ws?.close();
  }, []);

  return (
    <div className="onyx-card animate-in h-[400px] bg-[#050505] font-mono text-xs p-5 rounded-xl border border-cyan-900/50 shadow-[0_0_30px_rgba(0,255,255,0.05)] overflow-hidden flex flex-col">
      <h3 className="text-cyan-400 text-sm font-bold mb-4 flex items-center uppercase tracking-widest border-b border-cyan-900/50 pb-2">
        <span className="w-2 h-2 rounded-full bg-cyan-500 animate-[ping_1.5s_cubic-bezier(0,0,0.2,1)_infinite] mr-3"></span>
        SciBERT NLP Extractions 
      </h3>
      <div className="flex-1 overflow-y-auto space-y-3">
        {stream.map((item, idx) => (
          <div key={idx} style={{ animation: 'fadeIn 0.5s ease-out' }} className="border-l-2 border-cyan-500/30 pl-3 bg-cyan-900/10 p-2 rounded">
            <p className="text-gray-400 mb-2 italic">"{item.raw}"</p>
            <div className="flex gap-2 flex-wrap">
              {item.entities.map((e, i) => (
                <span key={i} className="px-2 py-0.5 bg-cyan-900/40 text-cyan-200 rounded-sm border border-cyan-500/40">
                  <strong className="text-cyan-500 mr-1">[{e.label}]</strong>{e.text} 
                  <span className="text-cyan-700 ml-1">{(e.conf * 100).toFixed(0)}%</span>
                </span>
              ))}
            </div>
          </div>
        ))}
        <style dangerouslySetInnerHTML={{__html: `
          @keyframes fadeIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
        `}} />
      </div>
    </div>
  );
}
