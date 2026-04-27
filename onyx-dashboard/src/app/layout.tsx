import type { Metadata } from 'next';
import '@/styles/globals.css';
import dynamic from 'next/dynamic';
import LiveDataProvider from '@/components/LiveDataProvider';

// SSR-safe dynamic import: deep-chat is a Web Component and cannot render on the server.
const OnyxCopilot = dynamic(() => import('@/components/OnyxCopilot'), {
  ssr: false,
});

export const metadata: Metadata = {
  title: 'ONYX CTI — Centre de Commandement',
  description: 'Plateforme souveraine de renseignement sur les cybermenaces — Suivi IOC temps réel, surveillance du Dark Web et cartographie ATT&CK.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr">
      <body>
        <LiveDataProvider>
          {children}
          {/* Global floating chatbot — visible on every page */}
          <OnyxCopilot />
        </LiveDataProvider>
      </body>
    </html>
  );
}
