import type { Metadata } from 'next';
import '@/styles/globals.css';
import dynamic from 'next/dynamic';

// SSR-safe dynamic import: deep-chat is a Web Component and cannot render on the server.
const OnyxCopilot = dynamic(() => import('@/components/OnyxCopilot'), {
  ssr: false,
});

export const metadata: Metadata = {
  title: 'ONYX CTI — Command Center',
  description: 'Sovereign Cyber Threat Intelligence Platform — Real-time IOC tracking, dark web monitoring, and ATT&CK mapping.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {children}
        {/* Global floating chatbot — visible on every page */}
        <OnyxCopilot />
      </body>
    </html>
  );
}
