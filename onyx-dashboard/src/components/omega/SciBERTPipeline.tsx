"use client";
import React, { useRef, useState, useCallback, useEffect } from 'react';
import { useOmegaStore, NLPEntity } from '../../lib/store/omegaStore';

// --- Neural Highlight Styles ---
const ENTITY_STYLES: Record<NLPEntity['type'], {
  bg: string; text: string; border: string; label: string; glow: string;
}> = {
  actor:   { bg: 'bg-rose-500/20',   text: 'text-rose-400',   border: 'border-rose-500/80',   label: 'ACTOR',   glow: 'shadow-[0_0_15px_rgba(244,63,94,0.4)]' },
  ttp:     { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/80', label: 'TTP',     glow: 'shadow-[0_0_15px_rgba(249,115,22,0.4)]' },
  malware: { bg: 'bg-purple-500/20', text: 'text-purple-400', border: 'border-purple-500/80', label: 'MALWARE', glow: 'shadow-[0_0_15px_rgba(168,85,247,0.4)]' },
  cve:     { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/80', label: 'CVE',     glow: 'shadow-[0_0_15px_rgba(234,179,8,0.4)]' },
  org:     { bg: 'bg-blue-500/20',   text: 'text-blue-400',   border: 'border-blue-500/80',   label: 'ORG',     glow: 'shadow-[0_0_15px_rgba(59,130,246,0.4)]' },
  infra:   { bg: 'bg-cyan-500/20',   text: 'text-cyan-400',   border: 'border-cyan-500/80',   label: 'INFRA',   glow: 'shadow-[0_0_15px_rgba(6,182,212,0.4)]' },
};

function LiveMatrixOverlay({ isAnalyzing }: { isAnalyzing: boolean }) {
  if (!isAnalyzing) return null;
  return (
    <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden opacity-10">
      <div className="absolute top-0 left-0 w-full h-[200%] bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyMCIgaGVpZ2h0PSIyMCI+PHBhdGggZD0iTTEgMWgydjJIMUMxem00IDBoMnYySDV6IiBmaWxsPSIjMTRiOGE2IiBmaWxsLXJ1bGU9ImV2ZW5vZGQiLz48L3N2Zz4=')] animate-[slide_10s_linear_infinite]" />
    </div>
  );
}

function AnnotatedText({ text, entities }: { text: string; entities: NLPEntity[] }) {
  if (!text) return null;
  const sorted = [...entities].sort((a, b) => a.start - b.start);
  const segments: React.ReactNode[] = [];
  let cursor = 0;

  sorted.forEach((ent, i) => {
    if (ent.start > cursor) {
      segments.push(<span key={`plain-${i}`} className="text-slate-300">{text.slice(cursor, ent.start)}</span>);
    }
    const style = ENTITY_STYLES[ent.type];
    segments.push(
      <span key={`ent-${i}`} className="relative inline-block mx-0.5 group z-10">
        <span className={`px-1.5 py-0.5 rounded border ${style.bg} ${style.text} ${style.border} ${style.glow} font-bold cursor-crosshair transition-all duration-300 group-hover:bg-opacity-40`}>
          {text.slice(ent.start, ent.end)}
        </span>
        <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 rounded border border-slate-700 bg-slate-900/95 shadow-2xl backdrop-blur-md opacity-0 scale-95 group-hover:opacity-100 group-hover:scale-100 transition-all duration-200 pointer-events-none whitespace-nowrap text-left z-50">
          <span className={`block text-[10px] uppercase tracking-widest font-black mb-1 ${style.text}`}>{style.label}</span>
          <span className="block text-xs text-slate-300 font-mono">Neural Confidence: <span className="text-emerald-400">{(ent.confidence * 100).toFixed(2)}%</span></span>
        </span>
      </span>
    );
    cursor = ent.end;
  });

  if (cursor < text.length) segments.push(<span key="plain-tail" className="text-slate-300">{text.slice(cursor)}</span>);
  return <>{segments}</>;
}

export default function SciBERTPipeline() {
  const { nlpInputText, nlpEntities, nlpIsAnalyzing, setNlpInputText, setNlpEntities, setNlpIsAnalyzing, addTTPObservation } = useOmegaStore();
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const runNLP = useCallback(async (text: string) => {
    if (!text.trim()) { setNlpEntities([]); return; }
    setNlpIsAnalyzing(true);
    try {
      const res = await fetch('/api/nlp/analyze', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }), signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const { entities }: { entities: NLPEntity[] } = await res.json();
        setNlpEntities(entities);
        entities.filter((e) => e.type === 'ttp').forEach((e) => {
          addTTPObservation({ id: e.text, name: e.text, tactic: 'Dynamic Extracted', confidence: e.confidence, ts: Date.now(), sourceActors: [] });
        });
      } else setNlpEntities([]);
    } catch { setNlpEntities([]); } finally { setNlpIsAnalyzing(false); }
  }, [setNlpEntities, setNlpIsAnalyzing, addTTPObservation]);

  const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    setNlpInputText(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => runNLP(val), 600);
  };

  return (
    <div className="flex flex-col bg-[#050914] border border-cyan-500/20 rounded-xl overflow-hidden shadow-[0_0_30px_rgba(6,182,212,0.05)] h-[600px] relative">
      <div className="flex items-center justify-between px-6 py-4 border-b border-cyan-500/20 bg-[#0a1020]/80 backdrop-blur-md relative z-10">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className={`w-3 h-3 rounded-full ${nlpIsAnalyzing ? 'bg-cyan-400 animate-pulse' : 'bg-emerald-400 shadow-[0_0_10px_#34d399]'}`} />
            {nlpIsAnalyzing && <div className="absolute inset-0 rounded-full border border-cyan-400 animate-ping" />}
          </div>
          <div>
            <h2 className="text-sm font-black text-cyan-50 uppercase tracking-[0.2em] font-mono">SciBERT Neural Engine</h2>
            <p className="text-[10px] text-cyan-500/70 uppercase tracking-widest mt-0.5">Real-Time Threat Vector Extraction</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {nlpIsAnalyzing && <span className="text-xs text-cyan-400 font-mono animate-pulse">Running semantic tensor stream...</span>}
          {nlpEntities.length > 0 && (
            <span className="px-3 py-1 bg-cyan-500/10 border border-cyan-500/40 text-cyan-400 text-xs font-mono rounded font-bold">
              {nlpEntities.length} Vectors Extracted
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 h-full divide-x divide-cyan-500/20 relative z-10">
        <div className="flex flex-col relative bg-[#080d1a]">
          <div className="px-4 py-2 border-b border-cyan-500/20 bg-cyan-950/20 flex justify-between">
            <span className="text-[10px] text-cyan-500 uppercase tracking-widest font-mono">Raw CTI Feed Input</span>
          </div>
          <textarea
            className="flex-1 p-6 bg-transparent text-slate-300 font-mono text-sm leading-relaxed resize-none outline-none placeholder:text-slate-700 z-10"
            placeholder="Ingest unstructured CTI reports, raw pastebins, or dark web intel. The neural engine will instantly map entities..."
            value={nlpInputText} onChange={handleInput} spellCheck={false}
          />
        </div>
        
        <div className="flex flex-col relative bg-[#040710] overflow-hidden">
          <LiveMatrixOverlay isAnalyzing={nlpIsAnalyzing} />
          <div className="px-4 py-2 border-b border-cyan-500/20 bg-cyan-950/20 flex justify-between z-10">
            <span className="text-[10px] text-cyan-500 uppercase tracking-widest font-mono">Neural Mapped Topology</span>
          </div>
          <div className="flex-1 p-6 font-mono text-sm leading-[2.5] overflow-auto z-10">
            {!nlpInputText.trim() ? (
              <div className="h-full flex flex-col items-center justify-center gap-4 text-cyan-500/30">
                <div className="text-5xl mb-2">⌬</div>
                <p className="text-xs uppercase tracking-widest text-center">Awaiting Data Stream<br/>for Semantic Processing</p>
              </div>
            ) : (
              <div className="relative">
                <AnnotatedText text={nlpInputText} entities={nlpEntities} />
              </div>
            )}
          </div>
        </div>
      </div>
      
      <div className="px-6 py-3 border-t border-cyan-500/20 bg-[#0a1020]/90 z-10 flex gap-4 overflow-x-auto no-scrollbar">
        {(Object.entries(ENTITY_STYLES) as [NLPEntity['type'], typeof ENTITY_STYLES[NLPEntity['type']]][]).map(([type, style]) => (
          <div key={type} className={`flex items-center gap-2 px-2 py-1 rounded border text-[10px] font-mono uppercase font-bold tracking-widest ${style.bg} ${style.text} ${style.border}`}>
            <div className={`w-2 h-2 rounded-full ${style.text.replace('text-', 'bg-')} shadow-[0_0_8px_currentColor]`} />
            {style.label}
          </div>
        ))}
      </div>
    </div>
  );
}
