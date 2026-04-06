"use client";

import React, { useEffect, useState, useMemo } from 'react';
import DeckGL from '@deck.gl/react';
import { GeoJsonLayer, ArcLayer, ScatterplotLayer } from '@deck.gl/layers';
import { Map } from 'react-map-gl/maplibre';

const INITIAL_VIEW_STATE = {
  longitude: 10,
  latitude: 30,
  zoom: 1.5,
  maxZoom: 16,
  pitch: 45,
  bearing: 0
};

const MAP_STYLE = 'https://basemaps.cartocdn.com/gl/dark-matter-nolabels-gl-style/style.json';

const MAJOR_CITIES = [
  { lon: -74.0, lat: 40.7, name: 'United States', ip: '45.142.212.100' },
  { lon: 37.6, lat: 55.75, name: 'Russian Federation', ip: '185.220.101.45' },
  { lon: 116.4, lat: 39.9, name: 'China', ip: '114.114.114.114' },
  { lon: -0.12, lat: 51.5, name: 'United Kingdom', ip: '91.108.56.181' },
  { lon: 34.8, lat: 31.0, name: 'Israel', ip: '77.83.36.18' }
];

export default function ThreatMap3D() {
  const [arcs, setArcs] = useState<any[]>([]);
  const [geoData, setGeoData] = useState(null);
  const [hoverInfo, setHoverInfo] = useState<any>(null);

  // Load GeoJSON borders
  useEffect(() => {
    fetch('https://d2ad6b4ur7yvpq.cloudfront.net/naturalearth-3.3.0/ne_50m_admin_0_scale_rank.geojson')
      .then(res => res.json())
      .then(data => setGeoData(data))
      .catch(console.error);
  }, []);

  // Simulate incoming attacks
  useEffect(() => {
    const t = setInterval(() => {
      const srcIdx = Math.floor(Math.random() * MAJOR_CITIES.length);
      let dstIdx = Math.floor(Math.random() * MAJOR_CITIES.length);
      while(dstIdx === srcIdx) dstIdx = Math.floor(Math.random() * MAJOR_CITIES.length);
      
      const src = MAJOR_CITIES[srcIdx];
      const dst = MAJOR_CITIES[dstIdx];

      setArcs(prev => [
        ...prev.slice(-30),
        {
          source: [src.lon, src.lat],
          target: [dst.lon, dst.lat],
          srcName: src.name,
          dstName: dst.name,
          srcIp: src.ip,
          timestamp: Date.now(),
          color: [255, Math.floor(Math.random() * 100), 0]
        }
      ]);
    }, 1200);
    return () => clearInterval(t);
  }, []);

  const activeCountries = useMemo(() => {
    const set = new Set<string>();
    arcs.forEach(a => {
      set.add(a.srcName);
      set.add(a.dstName);
    });
    return set;
  }, [arcs]);

  const layers = [
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
          return [239, 68, 68, 80]; // Pulsing red for active zones
        }
        return [0, 0, 0, 0];
      },
      updateTriggers: {
        getFillColor: activeCountries
      }
    }),
    
    // 2. Nodes (Impact / Source zones)
    new ScatterplotLayer({
      id: 'nodes-layer',
      data: MAJOR_CITIES,
      getPosition: d => [d.lon, d.lat],
      getFillColor: [0, 238, 255, 200],
      getRadius: 100000,
      radiusScale: 2,
      radiusMinPixels: 4,
      radiusMaxPixels: 12,
      stroked: true,
      getLineColor: [0, 238, 255],
      lineWidthMinPixels: 2
    }),

    // 3. Attack Vectors
    new ArcLayer({
      id: 'attack-arcs',
      data: arcs,
      getSourcePosition: d => d.source,
      getTargetPosition: d => d.target,
      getSourceColor: d => [...d.color, 255],
      getTargetColor: d => [0, 238, 255, 255],
      getWidth: 3,
      pickable: true,
      onHover: info => setHoverInfo(info)
    })
  ];

  return (
    <div style={{ position: 'relative', width: '100%', height: '400px', background: '#050a0f', borderRadius: '12px', overflow: 'hidden', border: '1px solid rgba(0, 238, 255, 0.2)', boxShadow: '0 0 50px rgba(0,0,0,0.8) inset' }}>
      <div style={{ position: 'absolute', top: 12, left: 16, zIndex: 10, fontFamily: 'monospace', fontSize: '11px', color: '#ff0040', background: 'rgba(5, 10, 15, 0.9)', padding: '6px 12px', borderRadius: '4px', border: '1px solid rgba(255,0,64,0.4)', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ff0040', display: 'inline-block', boxShadow: '0 0 8px #ff0040' }} className="pulse-live" />
        GEOPOLITICAL THREAT MATRIX
      </div>

      <DeckGL
        layers={layers}
        initialViewState={INITIAL_VIEW_STATE}
        controller={true}
        getCursor={() => 'crosshair'}
      >
        <Map
          mapStyle={MAP_STYLE}
          attributionControl={false}
        />
      </DeckGL>

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
          <div style={{ marginBottom: 4 }}>
            <span style={{ color: '#ef4444', fontWeight: 'bold' }}>Source: </span>
            {hoverInfo.object.srcName} ({hoverInfo.object.srcIp})
          </div>
          <div>
            <span style={{ color: '#00eeff', fontWeight: 'bold' }}>Target: </span>
            {hoverInfo.object.dstName}
          </div>
        </div>
      )}
    </div>
  );
}
