import React, { useEffect, useState } from 'react';

interface PedagogyData {
  technique_info: {
    id: string;
    name: string;
    description: string;
    objective: string;
    example?: string;
  };
  live_iocs: Array<{
    id: string;
    value: string;
    type: string;
    severity: string;
    source: string;
    confidence: number;
  }>;
  threat_actors: Array<{
    id: string;
    name: string;
    description: string;
  }>;
  mitigation: string;
}

interface SlideOverProps {
  technique: string | null;
  onClose: () => void;
  heatmapCount: number;
  avgConfidence: number;
}

export default function SlideOver({ technique, onClose, heatmapCount, avgConfidence }: SlideOverProps) {
  const [data, setData] = useState<PedagogyData | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    if (!technique) {
        setData(null);
        return;
    }

    let isMounted = true;
    setLoading(true);
    
    // Async fetching of deep correlation data
    fetch(`http://localhost:8000/api/v1/mitre/technique/${technique}`)
        .then(res => res.json())
        .then((payload) => {
            if (isMounted) {
                setData(payload);
                setLoading(false);
            }
        })
        .catch(err => {
            console.error("Deep correlation payload fetch failed:", err);
            if (isMounted) setLoading(false);
        });

    return () => { isMounted = false; };
  }, [technique]);

  if (!technique) return null;

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 bg-[#0a0f1a] border border-[#1e293b] rounded-lg p-5 shadow-2xl mt-2 relative">
      <button 
        className="absolute top-4 right-4 text-[#64748b] hover:text-white"
        onClick={onClose}
      >✕</button>

      <div className="flex gap-8 items-start">
        {/* LEFT COLUMN: Metadata & Metrics */}
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-xl font-black text-[#00eeff]">{technique}</span>
            <span className="text-lg font-bold text-white">
              {data ? data.technique_info.name : "Loading..."}
            </span>
          </div>
          
          <div className="flex gap-4 mt-4">
             <div className="bg-[#1e293b]/50 px-4 py-2 rounded border border-[#334155]">
               <div className="text-[10px] text-[#94a3b8] font-bold">LIVE DETECTIONS</div>
               <div className="text-lg font-mono text-[#00eeff] font-bold">{heatmapCount}</div>
             </div>
             {heatmapCount > 0 && (
               <div className="bg-[#1e293b]/50 px-4 py-2 rounded border border-[#334155]">
                 <div className="text-[10px] text-[#94a3b8] font-bold">AVG CONFIDENCE</div>
                 <div className="text-lg font-mono text-[#22c55e] font-bold">{Math.round(avgConfidence)}%</div>
               </div>
             )}
          </div>
          
          {/* Threat Actors block */}
          {data && data.threat_actors.length > 0 && (
            <div className="mt-6">
              <div className="text-[10px] uppercase text-[#f59e0b] font-bold tracking-wider mb-2">KNOWN TACTICAL ADOPTION</div>
              <div className="flex flex-wrap gap-2">
                  {data.threat_actors.map(ta => (
                      <span key={ta.id} className="text-xs bg-purple-900/30 text-purple-300 border border-purple-500/40 px-2 py-1 rounded" title={ta.description}>
                          {ta.name}
                      </span>
                  ))}
              </div>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: The Intelligence */}
        <div className="flex-[2] bg-black/40 p-4 rounded border-l-[3px] border-[#ef4444] text-sm max-h-[400px] overflow-y-auto custom-scrollbar">
          {loading || !data ? (
            <div className="text-[#64748b] animate-pulse py-4 font-mono text-xs">Fetching classified correlation intelligence...</div>
          ) : (
            <div className="flex flex-col gap-3">
              <div>
                <span className="text-[#ef4444] font-bold uppercase text-[10px] tracking-wider block mb-1">EXECUTION MECHANISM (WHAT IS IT?)</span>
                <p className="text-[#cbd5e1] text-xs pb-1">{data.technique_info.description}</p>
              </div>
              
              {data.technique_info.example && (
                <div className="bg-purple-900/10 border-l-2 border-[#a855f7] pl-3 py-2 rounded-r">
                  <span className="text-[#a855f7] font-bold uppercase text-[10px] tracking-wider block mb-1">CONCRETE EXAMPLE</span>
                  <p className="text-[#e2e8f0] italic text-xs">{data.technique_info.example}</p>
                </div>
              )}

              <div className="mt-1">
                <span className="text-[#f59e0b] font-bold uppercase text-[10px] tracking-wider block mb-1">BUSINESS IMPACT (WHY IT MATTERS)</span>
                <p className="text-[#cbd5e1] text-xs pb-1">{data.technique_info.objective}</p>
              </div>
              
              <div className="bg-[#ef4444]/10 p-3 rounded border border-[#ef4444]/30 mt-2">
                <span className="text-[#00eeff] font-bold uppercase text-[10px] tracking-wider block mb-1 flex items-center gap-2">
                  <span className="w-1.5 h-1.5 bg-[#00eeff] rounded-full"></span> ACTIONABLE MITIGATION
                </span>
                <p className="text-white font-mono text-xs mt-1 leading-relaxed">{data.mitigation}</p>
              </div>
              
              {/* LIVE IOC CORRELATION BLOCK */}
              <div className="mt-4 border-t border-[#334155] pt-4">
                  <span className="text-[#00eeff] font-bold uppercase text-[10px] tracking-wider block mb-2">LIVE IOC CORRELATION</span>
                  {data.live_iocs.length === 0 ? (
                      <div className="text-xs text-[#64748b] font-mono">No live IOCs currently mapped to this exact node.</div>
                  ) : (
                      <div className="grid grid-cols-2 gap-2">
                          {data.live_iocs.map(ioc => (
                              <div key={ioc.id} className="flex justify-between items-center text-[10px] bg-[#1e293b] border border-[#475569] px-2 py-1.5 rounded">
                                  <span className="font-mono text-[#cbd5e1] truncate mr-2" title={ioc.value}>{ioc.value}</span>
                                  <div className="flex gap-1 shrink-0">
                                      <span className={`px-1.5 py-0.5 rounded uppercase ${ioc.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                                          {ioc.type}
                                      </span>
                                  </div>
                              </div>
                          ))}
                      </div>
                  )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
