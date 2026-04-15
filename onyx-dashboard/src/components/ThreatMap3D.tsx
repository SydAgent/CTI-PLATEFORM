"use client";

import React, { useEffect, useState, useMemo, useRef, useCallback } from 'react';
import { useOnyxStore } from '@/lib/store';

// Removed static WebGL imports to prevent maxTextureDimension2D SSR crash
// Dependencies will be lazy-loaded in useEffect

const INITIAL_VIEW_STATE = {
  longitude: 10,
  latitude: 30,
  zoom: 1.5,
  maxZoom: 16,
  pitch: 45,
  bearing: 0
};

const MAP_STYLE = 'https://basemaps.cartocdn.com/gl/dark-matter-nolabels-gl-style/style.json';

// ── SEVERITY → COLOR MAPPING ──
const SEVERITY_COLORS: Record<string, [number, number, number]> = {
  critical: [239, 68, 68],   // Red
  high:     [249, 115, 22],  // Orange
  medium:   [234, 179, 8],   // Yellow
  low:      [34, 197, 94],   // Green
};

export default function ThreatMap3D({ liveEvents = [] }: { liveEvents?: any[] }) {
  // ── Zustand store subscription for live events ──
  const storeEvents = useOnyxStore(s => s.events);
  
  const [DeckGL, setDeckGL] = useState<any>(null);
  const [deckLayers, setDeckLayers] = useState<any>(null);
  const [MapGL, setMapGL] = useState<any>(null);

  const [verifiedArcs, setVerifiedArcs] = useState<any[]>([]);
  const [threatSources, setThreatSources] = useState<any[]>([]);
  const [geoData, setGeoData] = useState(null);
  const [hoverInfo, setHoverInfo] = useState<any>(null);
  const [isWebGLSupported, setIsWebGLSupported] = useState<boolean | null>(null);
  const [lastSync, setLastSync] = useState(Date.now());
  const [syncStr, setSyncStr] = useState('0');
  const [pulseSync, setPulseSync] = useState(false);
  const [geoArticles, setGeoArticles] = useState<any[]>([]);
  const [geoMarkers, setGeoMarkers] = useState<any[]>([]);
  const [pulsePhase, setPulsePhase] = useState(0);

  // Animate scatter pulse
  useEffect(() => {
    const t = setInterval(() => setPulsePhase(p => (p + 1) % 120), 50);
    return () => clearInterval(t);
  }, []);

  // Poll geopolitical threats from backend every 30s
  useEffect(() => {
    const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    const fetchGeo = () => {
      fetch(`${API}/api/v1/dashboard/geopolitical/threats`)
        .then(r => r.json())
        .then(data => {
          if (data.threats) setGeoArticles(data.threats.slice(0, 10));
          if (data.markers) setGeoMarkers(data.markers);
          setLastSync(Date.now());
          setPulseSync(true);
          setTimeout(() => setPulseSync(false), 800);
        })
        .catch(() => {});
    };
    fetchGeo();
    const interval = setInterval(fetchGeo, 30_000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const t = setInterval(() => {
      setSyncStr(Math.floor((Date.now() - lastSync) / 1000).toString());
    }, 1000);
    return () => clearInterval(t);
  }, [lastSync]);

  // WebGL Support Detection
  useEffect(() => {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    setIsWebGLSupported(!!gl);
  }, []);

  // Lazy-load WebGL components only if supported
  useEffect(() => {
    if (isWebGLSupported === false) return;
    Promise.all([
      import('@deck.gl/react'),
      import('@deck.gl/layers'),
      import('react-map-gl/maplibre')
    ]).then(([deck, layers, mapgl]) => {
      setDeckGL(() => deck.default);
      setDeckLayers(layers);
      setMapGL(() => mapgl.Map);
    }).catch(console.error);
  }, []);

  // Load GeoJSON borders
  useEffect(() => {
    fetch('https://d2ad6b4ur7yvpq.cloudfront.net/naturalearth-3.3.0/ne_50m_admin_0_scale_rank.geojson')
      .then(res => res.json())
      .then(data => setGeoData(data))
      .catch(console.error);
  }, []);

  // ── Real-time Mapping of Incoming Events ──
  // REFACTORED: No more fake Paris targeting. 
  // Events with source+target geo → ArcLayer (verified bidirectional)
  // Events with source-only geo → ScatterplotLayer (threat pulse)
  useEffect(() => {
    const allEvents = [
      ...(liveEvents || []),
      ...storeEvents,
    ];

    if (allEvents.length === 0) return;

    // Filter events that have at least source geolocation
    const geoEvents = allEvents
      .filter((ev: any) => {
        const evType = ev.event_type || ev.type;
        const hasGeo = ev.data?.geolocation || ev.geolocation;
        return evType === 'ioc_detected' && hasGeo;
      })
      .slice(-100);

    if (geoEvents.length === 0) return;

    const newArcs: any[] = [];
    const newSources: any[] = [];

    geoEvents.forEach((ev) => {
      const srcGeo = ev.data?.geolocation || ev.geolocation;
      const tgtGeo = ev.data?.target_geolocation || ev.target_geolocation;

      if (srcGeo && tgtGeo && tgtGeo.longitude && tgtGeo.latitude) {
        // ── VERIFIED BIDIRECTIONAL ARC ──
        // Both source and target geolocation are present in the event data
        newArcs.push({
          source: [srcGeo.longitude, srcGeo.latitude],
          target: [tgtGeo.longitude, tgtGeo.latitude],
          srcName: `${srcGeo.country || 'Unknown'} (${srcGeo.city || 'Unknown'})`,
          dstName: `${tgtGeo.country || 'Unknown'} (${tgtGeo.city || 'Unknown'})`,
          srcIp: ev.data?.value || ev.value || 'N/A',
          timestamp: new Date(ev.timestamp || Date.now()).getTime(),
          color: (ev.data?.confidence ?? 50) > 90 ? [255, 60, 92] : [255, 165, 0],
        });
      } else if (srcGeo) {
        // ── SOURCE-ONLY THREAT PULSE ──
        // Only source geolocation known — render as scatter pulse, never fabricate a target
        const severity = ev.data?.severity || ev.severity || 'high';
        newSources.push({
          position: [srcGeo.longitude, srcGeo.latitude],
          name: `${srcGeo.country || 'Unknown'} (${srcGeo.city || 'Unknown'})`,
          ip: ev.data?.value || ev.value || 'N/A',
          severity: severity,
          confidence: ev.data?.confidence ?? 50,
          source: ev.data?.source || ev.source || 'OSINT',
          timestamp: new Date(ev.timestamp || Date.now()).getTime(),
          color: SEVERITY_COLORS[severity] || SEVERITY_COLORS.high,
        });
      }
    });

    // Also add backend geopolitical markers as threat sources
    geoMarkers.forEach((m: any) => {
      if (m.lat && m.lon) {
        newSources.push({
          position: [m.lon, m.lat],
          name: m.country || 'Unknown',
          ip: `${m.count || 0} indicators`,
          severity: 'high',
          confidence: 80,
          source: 'Geopolitical Intel',
          timestamp: Date.now(),
          color: SEVERITY_COLORS.high,
          count: m.count || 1,
        });
      }
    });

    setVerifiedArcs(newArcs);
    setThreatSources(newSources);

    setLastSync(Date.now());
    setPulseSync(true);
    setTimeout(() => setPulseSync(false), 800);
  }, [liveEvents, storeEvents, geoMarkers]);

  const activeCountries = useMemo(() => {
    const set = new Set<string>();
    verifiedArcs.forEach(a => {
      set.add(a.srcName);
      set.add(a.dstName);
    });
    threatSources.forEach(s => {
      set.add(s.name);
    });
    return set;
  }, [verifiedArcs, threatSources]);

  // Animated pulse radius
  const pulseRadius = useMemo(() => {
    const phase = pulsePhase / 120;
    return 20000 + Math.sin(phase * Math.PI * 2) * 15000;
  }, [pulsePhase]);

  const layersList = useMemo(() => {
    if (!deckLayers) return [];
    const { GeoJsonLayer, ScatterplotLayer, ArcLayer } = deckLayers;

    return [
      // 1. Geopolitical Boundaries
      new GeoJsonLayer({
        id: 'geojson-borders',
        data: geoData,
        pickable: true,
        stroked: true,
        filled: true,
        lineWidthMinPixels: 1,
        getLineColor: [0, 238, 255, 60],
        getFillColor: (d: any) => {
          const countryName = d.properties.admin || d.properties.name;
          if (activeCountries.has(countryName)) {
            return [239, 68, 68, 80]; // Red for active zones
          }
          return [0, 0, 0, 0];
        },
        updateTriggers: {
          getFillColor: activeCountries
        }
      }),
      
      // 2. Threat Source Pulse Layer — massive pulsing nodes on malicious origins
      new ScatterplotLayer({
        id: 'threat-source-pulse-outer',
        data: threatSources,
        getPosition: (d: any) => d.position,
        getFillColor: (d: any) => [...d.color, 40],
        getRadius: (d: any) => (d.count || 1) * pulseRadius,
        radiusMinPixels: 8,
        radiusMaxPixels: 60,
        stroked: true,
        getLineColor: (d: any) => [...d.color, 80],
        lineWidthMinPixels: 1,
        pickable: true,
        onHover: (info: any) => setHoverInfo(info.object ? { ...info, layerType: 'source' } : null),
        updateTriggers: {
          getRadius: pulsePhase,
        }
      }),

      // 3. Threat Source Core — solid inner node
      new ScatterplotLayer({
        id: 'threat-source-core',
        data: threatSources,
        getPosition: (d: any) => d.position,
        getFillColor: (d: any) => [...d.color, 220],
        getRadius: 15000,
        radiusMinPixels: 4,
        radiusMaxPixels: 12,
        stroked: true,
        getLineColor: (d: any) => [...d.color, 255],
        lineWidthMinPixels: 2,
      }),

      // 4. Verified Attack Arcs — ONLY when both source AND target are confirmed
      new ArcLayer({
        id: 'verified-attack-arcs',
        data: verifiedArcs,
        getSourcePosition: (d: any) => d.source,
        getTargetPosition: (d: any) => d.target,
        getSourceColor: (d: any) => [...d.color, 255],
        getTargetColor: [0, 238, 255, 255],
        getWidth: 3,
        pickable: true,
        onHover: (info: any) => setHoverInfo(info.object ? { ...info, layerType: 'arc' } : null),
      })
    ];
  }, [verifiedArcs, threatSources, activeCountries, geoData, deckLayers, pulsePhase, pulseRadius]);

  if (isWebGLSupported === false) {
    return (
      <div style={{ position: 'relative', width: '100%', height: '400px', background: '#080c14', borderRadius: '12px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', border: '1px solid #ef4444' }}>
        <div style={{ fontSize: 28, marginBottom: 12 }}>⚠️</div>
        <div style={{ color: '#ef4444', fontFamily: 'monospace', fontSize: '12px', fontWeight: 'bold' }}>WEBGL HARDWARE ACCELERATION DISABLED</div>
        <div style={{ color: '#6b7280', fontFamily: 'monospace', fontSize: '10px', marginTop: 4 }}>[ FALLBACK: SECURE 2D MODE ACTIVE ]</div>
      </div>
    );
  }

  if (!DeckGL || !MapGL || isWebGLSupported === null) {
    return (
      <div style={{ position: 'relative', width: '100%', height: '400px', background: '#050a0f', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ color: '#00eeff', fontFamily: 'monospace', fontSize: '11px', opacity: 0.5 }}>Loading Secure GL Engine...</div>
      </div>
    );
  }

  return (
    <div style={{ position: 'relative', width: '100%', height: '400px', background: '#050a0f', borderRadius: '12px', overflow: 'hidden', border: pulseSync ? '1px solid rgba(255, 0, 64, 0.8)' : '1px solid rgba(0, 238, 255, 0.2)', boxShadow: pulseSync ? '0 0 80px rgba(255,0,64,0.3) inset' : '0 0 50px rgba(0,0,0,0.8) inset', transition: 'all 0.5s ease-out' }}>
      <div style={{ position: 'absolute', top: 12, left: 16, zIndex: 10, fontFamily: 'monospace', fontSize: '11px', color: '#ff0040', background: 'rgba(5, 10, 15, 0.9)', padding: '6px 12px', borderRadius: '4px', border: '1px solid rgba(255,0,64,0.4)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ff0040', display: 'inline-block', boxShadow: '0 0 8px #ff0040' }} className="pulse-live" />
          <span className="font-bold">GEOPOLITICAL THREAT MATRIX</span>
        </div>
        <div style={{ color: pulseSync ? '#ff3b5c' : '#6b7280', fontSize: '9px', fontWeight: 'bold' }}>
          LIVE · {threatSources.length} threat sources · {verifiedArcs.length} verified arcs · synced {syncStr}s ago
        </div>
      </div>

      <DeckGL
        layers={layersList}
        initialViewState={INITIAL_VIEW_STATE}
        controller={true}
        getCursor={() => 'crosshair'}
      >
        <MapGL
          mapStyle={MAP_STYLE}
          attributionControl={false}
        />
      </DeckGL>

      {/* Hover Tooltip — contextual for both arcs and threat sources */}
      {hoverInfo && hoverInfo.object && (
        <div style={{
          position: 'absolute',
          zIndex: 100,
          pointerEvents: 'none',
          left: hoverInfo.x,
          top: hoverInfo.y,
          background: 'rgba(0,0,0,0.9)',
          border: '1px solid #ef4444',
          color: '#e5e7eb',
          padding: '8px 12px',
          borderRadius: '4px',
          fontFamily: 'monospace',
          fontSize: '11px',
          transform: 'translate(-50%, -120%)',
          boxShadow: '0 0 15px rgba(239, 68, 68, 0.2)'
        }}>
          {hoverInfo.layerType === 'arc' ? (
            <>
              <div style={{ marginBottom: 4 }}>
                <span style={{ color: '#ef4444', fontWeight: 'bold' }}>Source: </span>
                {hoverInfo.object.srcName} ({hoverInfo.object.srcIp})
              </div>
              <div>
                <span style={{ color: '#00eeff', fontWeight: 'bold' }}>Target: </span>
                {hoverInfo.object.dstName}
              </div>
              <div style={{ marginTop: 4, color: '#22c55e', fontSize: '9px' }}>
                ✓ VERIFIED BIDIRECTIONAL VECTOR
              </div>
            </>
          ) : (
            <>
              <div style={{ marginBottom: 4 }}>
                <span style={{ color: '#ef4444', fontWeight: 'bold' }}>Threat Origin: </span>
                {hoverInfo.object.name}
              </div>
              <div>
                <span style={{ color: '#f59e0b', fontWeight: 'bold' }}>IOC: </span>
                {hoverInfo.object.ip}
              </div>
              <div style={{ marginTop: 4, display: 'flex', gap: 8 }}>
                <span style={{ color: '#6b7280', fontSize: '9px' }}>Source: {hoverInfo.object.source}</span>
                <span style={{ color: '#6b7280', fontSize: '9px' }}>Confidence: {hoverInfo.object.confidence}%</span>
              </div>
            </>
          )}
        </div>
      )}

      {/* Legend Badge */}
      <div style={{ position: 'absolute', top: 12, right: 16, zIndex: 10, fontFamily: 'monospace', fontSize: '10px', color: '#00eeff', background: 'rgba(5,10,15,0.9)', padding: '6px 10px', borderRadius: '4px', border: '1px solid rgba(0,238,255,0.3)', display: 'flex', flexDirection: 'column', gap: 3 }}>
        <div>{verifiedArcs.length} verified arcs · {threatSources.length} threat sources · {geoArticles.length} intel</div>
        <div style={{ display: 'flex', gap: 8, fontSize: '8px' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444', display: 'inline-block' }} /> Critical</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f97316', display: 'inline-block' }} /> High</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#eab308', display: 'inline-block' }} /> Medium</span>
        </div>
      </div>

      {/* Live Geopolitical Intelligence Ticker */}
      {geoArticles.length > 0 && (
        <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, zIndex: 10, background: 'rgba(5,10,15,0.92)', borderTop: '1px solid rgba(255,0,64,0.3)', padding: '6px 16px', display: 'flex', gap: '24px', overflow: 'hidden' }}>
          <span style={{ color: '#ff0040', fontFamily: 'monospace', fontSize: '9px', fontWeight: 'bold', whiteSpace: 'nowrap', flexShrink: 0 }}>⚡ LIVE INTEL</span>
          <div style={{ overflow: 'hidden', flex: 1 }}>
            <div style={{ display: 'flex', gap: '40px', animation: 'ticker-scroll 30s linear infinite', whiteSpace: 'nowrap' }}>
              {geoArticles.map((art: any, i: number) => (
                <span key={i} style={{ fontFamily: 'monospace', fontSize: '9px', color: '#94a3b8' }}>
                  <span style={{ color: '#f59e0b' }}>[{art.source}]</span> {art.title}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes ticker-scroll {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
      `}</style>
    </div>
  );
}
