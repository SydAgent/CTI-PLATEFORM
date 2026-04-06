import type { Metadata } from 'next';
import '@/styles/globals.css';

export const metadata: Metadata = {
  title: 'ONYX CTI — Command Center',
  description: 'Sovereign Cyber Threat Intelligence Platform — Real-time IOC tracking, dark web monitoring, and ATT&CK mapping.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
