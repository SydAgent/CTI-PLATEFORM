'use client';

import { useEffect } from 'react';
import { initLiveDataEngine, destroyLiveDataEngine } from '@/services/LiveDataEngine';

export default function LiveDataProvider({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    initLiveDataEngine();
    return () => destroyLiveDataEngine();
  }, []);

  return <>{children}</>;
}
