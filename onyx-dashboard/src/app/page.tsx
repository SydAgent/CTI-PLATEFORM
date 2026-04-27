/**
 * ONYX CTI — Root Page (Server Component)
 *
 * This file is intentionally a Server Component (NO 'use client' directive).
 * It uses next/dynamic with { ssr: false } to ensure the entire dashboard tree
 * — including deck.gl, react-force-graph-3d, and maplibre-gl — is NEVER
 * evaluated by Node.js. This is the ONLY pattern that guarantees elimination
 * of the maxTextureDimension2D / WebGPU SSR crash.
 *
 * Pattern reference: Next.js App Router docs — "Client-only third-party packages"
 */

import dynamic from 'next/dynamic';

// ─── The nuclear ssr:false guard ─────────────────────────────────────────────
// DashboardClient owns ALL state, hooks, and WebGL imports.
// By dynamically importing it here from a Server Component, Next.js guarantees
// that NOTHING inside DashboardClient's module graph runs on the server.
const DashboardClient = dynamic(
  () => import('@/components/DashboardClient'),
  {
    ssr: false,
    loading: () => (
      <div style={{
        width: '100vw',
        height: '100vh',
        background: '#03060a',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'monospace',
        gap: '16px',
      }}>
        <div style={{ fontSize: '2rem', opacity: 0.8 }}>◆</div>
        <div style={{ fontSize: '14px', color: '#00eeff', letterSpacing: '0.2em', textTransform: 'uppercase' }}>
          ONYX CTI — Initialisation du Centre de Commandement
        </div>
        <div style={{ fontSize: '11px', color: '#374151', letterSpacing: '0.1em' }}>
          Chargement de la matrice de renseignement sécurisée...
        </div>
      </div>
    ),
  }
);

export default function Page() {
  return <DashboardClient />;
}
