import { create } from 'zustand';
import { sanitizePayload } from './sanitizer';

export interface IOC {
  type: string;
  value: string;
  source: string;
  confidence: number;
}

export interface WSEvent {
  type: string;
  data: Record<string, unknown>;
  timestamp: string;
}

interface DashboardStats {
  iocs: { total_iocs?: { value: number }; by_type?: { buckets: Array<{ key: string; doc_count: number }> }; by_severity?: { buckets: Array<{ key: string; doc_count: number }> }; timeline_24h?: { buckets: Array<{ key_as_string: string; doc_count: number }> }; avg_confidence?: { value: number } };
  threats: { total_threats?: { value: number }; by_type?: { buckets: Array<{ key: string; doc_count: number }> } };
  stix: { types: Record<string, number>; total: number };
  crawlers: Array<{ crawler_id: string; status: string; last_run?: string }>;
}

// ═══════════════════════════════════════════════════════════════════════════
//  TRUST UX: Data Freshness Tracking (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

export type FreshnessState = 'fresh' | 'aging' | 'stale';

/** Compute data freshness from timestamp */
export function computeFreshness(lastSync: number): FreshnessState {
  const age = Date.now() - lastSync;
  if (age < 15_000) return 'fresh';   // <15s = fresh
  if (age < 60_000) return 'aging';   // <60s = aging
  return 'stale';                      // >60s = stale
}

/** Human-readable elapsed time */
export function formatSyncAge(lastSync: number): string {
  const age = Math.floor((Date.now() - lastSync) / 1000);
  if (age < 5) return 'à l\'instant';
  if (age < 60) return `il y a ${age}s`;
  if (age < 3600) return `il y a ${Math.floor(age / 60)}min`;
  return `il y a ${Math.floor(age / 3600)}h`;
}

// ═══════════════════════════════════════════════════════════════════════════
//  CORE STATE
// ═══════════════════════════════════════════════════════════════════════════

interface OnyxState {
  stats: DashboardStats | null;
  armedIocs: IOC[];
  events: WSEvent[];
  connected: boolean;
  liveIocCount: number;
  selectedEventId: string | null;
  selectedActorId: string | null;
  isFeedPaused: boolean;
  feedBuffer: WSEvent[];

  // ── Trust UX: Sync Tracking ───────────────────────────────────────────
  lastWsMessageAt: number;      // Timestamp of last WS message received
  lastDataRefreshAt: number;    // Timestamp of last API data refresh
  wsMessageCount: number;       // Total WS messages received in session
  reconnectCount: number;       // Number of WS reconnections

  // ── Focus Mode (Graph Investigation) ──────────────────────────────────
  focusedEntityId: string | null;

  // ── Actions ───────────────────────────────────────────────────────────
  setStats: (stats: DashboardStats | null) => void;
  setArmedIocs: (iocs: IOC[]) => void;
  setSelectedEventId: (id: string | null) => void;
  setSelectedActorId: (id: string | null) => void;
  setFocusedEntityId: (id: string | null) => void;
  connectWebSocket: () => void;
  disconnectWebSocket: () => void;
  pauseFeed: () => void;
  resumeFeed: () => void;
}

// Global scope queue for requestAnimationFrame batching
let eventQueue: WSEvent[] = [];
let iocQueue: IOC[] = [];
let isRafScheduled = false;

// Global WS instance to prevent multiple connections in React strict mode
let wsInstance: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectDelay = 1000;
// Ping interval stored at module level — avoids (ws as any) casts
let pingIntervalId: ReturnType<typeof setInterval> | null = null;

export const useOnyxStore = create<OnyxState>((set, get) => {

  const processBatch = () => {
    const currentState = get();
    if (eventQueue.length === 0 && iocQueue.length === 0) {
      isRafScheduled = false;
      return;
    }

    // ── Déduplication stricte par clé composite source::type::value::(cveID|hash|id) ────────────────────────
    const buildDedupKey = (ioc: IOC) => {
      const extra = (ioc as any).cveID ?? (ioc as any).hash ?? (ioc as any).id ?? '';
      return `${ioc.source}::${ioc.type}::${ioc.value}::${extra}`;
    };

    // Construire une Map des IOC existants indexés par clé composite
    const existingMap = new Map<string, IOC>();
    for (const ioc of currentState.armedIocs) {
      existingMap.set(buildDedupKey(ioc), ioc);
    }

    // Filtrer les nouveaux IOCs — ne garder que ceux absents de la Map
    const uniqueNewIocs: IOC[] = [];
    for (const ioc of iocQueue) {
      const key = buildDedupKey(ioc);
      if (!existingMap.has(key)) {
        existingMap.set(key, ioc); // prévient les doublons intra-batch
        uniqueNewIocs.push(ioc);
      }
    }

    set({
      // Keep feed fast: strictly up to 150 events
      events: [...eventQueue.reverse(), ...currentState.events].slice(0, 150),
      armedIocs: [...uniqueNewIocs.reverse(), ...currentState.armedIocs],
      liveIocCount: currentState.liveIocCount + uniqueNewIocs.length,
    });

    eventQueue = [];
    iocQueue = [];
    isRafScheduled = false;
  };

  const scheduleBatch = () => {
    if (!isRafScheduled) {
      isRafScheduled = true;
      requestAnimationFrame(processBatch);
    }
  };

  return {
    stats: null,
    armedIocs: [],
    events: [],
    connected: false,
    liveIocCount: 0,
    selectedEventId: null,
    selectedActorId: null,
    isFeedPaused: false,
    feedBuffer: [],

    // Trust UX defaults
    lastWsMessageAt: 0,
    lastDataRefreshAt: Date.now(),
    wsMessageCount: 0,
    reconnectCount: 0,

    // Focus Mode
    focusedEntityId: null,

    setStats: (stats) => set({ stats, lastDataRefreshAt: Date.now() }),
    setArmedIocs: (iocs) => set({ armedIocs: iocs, lastDataRefreshAt: Date.now() }),
    setSelectedEventId: (id) => set({ selectedEventId: id }),
    setSelectedActorId: (id) => set({ selectedActorId: id }),
    setFocusedEntityId: (id) => set({ focusedEntityId: id }),

    pauseFeed: () => set({ isFeedPaused: true }),
    resumeFeed: () => {
      const { feedBuffer } = get();
      // Drain buffer into main event queue in a single batch
      if (feedBuffer.length > 0) {
        for (const evt of feedBuffer) {
          eventQueue.push(evt);
          if (evt.type === 'ioc_detected' && evt.data) {
            iocQueue.push(evt.data as unknown as IOC);
          }
        }
        scheduleBatch();
      }
      set({ isFeedPaused: false, feedBuffer: [] });
    },

    connectWebSocket: () => {
      if (wsInstance) {
        return; // Already connecting or connected
      }

      if (reconnectTimer) clearTimeout(reconnectTimer);

      const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const wsUrl = API.replace(/^http/, 'ws') + '/ws/events';
      
      try {
        wsInstance = new WebSocket(wsUrl);

        wsInstance.onopen = () => {
          set({ connected: true });
          reconnectDelay = 1000;
          
          pingIntervalId = setInterval(() => {
            if (wsInstance?.readyState === WebSocket.OPEN) {
              wsInstance.send(JSON.stringify({ type: 'ping' }));
            } else {
              if (pingIntervalId !== null) clearInterval(pingIntervalId);
              pingIntervalId = null;
            }
          }, 15000);
        };

        wsInstance.onmessage = (event) => {
          try {
            // Security: Strictly enforce DOMPurify sanitization
            const rawMsg = JSON.parse(event.data);
            const msg = sanitizePayload(rawMsg);
            
            // ── Trust UX: Track every message for freshness ──────────
            const now = Date.now();
            set(s => ({
              lastWsMessageAt: now,
              wsMessageCount: s.wsMessageCount + 1,
            }));

            if (msg.channel === 'heartbeat' || msg.payload?.type === 'pong' || msg.channel === 'system') {
               set({ connected: true });
               return;
            }

            const newEvent: WSEvent = {
              type: msg.channel || msg.payload?.type || 'unknown',
              data: msg.payload || {},
              timestamp: msg.ts || new Date().toISOString(),
            };

            // PAUSE/RESUME: buffer events when paused instead of pushing to render queue
            if (get().isFeedPaused) {
              set((state) => ({ feedBuffer: [...state.feedBuffer, newEvent].slice(-500) }));
              return;
            }

            eventQueue.push(newEvent);

            if (newEvent.type === 'ioc_detected' && newEvent.data) {
                iocQueue.push(newEvent.data as unknown as IOC);
            }

            scheduleBatch();

          } catch (e) {
             console.error("WS Engine error parsing message:", e);
          }
        };

        wsInstance.onclose = () => {
          if (pingIntervalId !== null) {
            clearInterval(pingIntervalId);
            pingIntervalId = null;
          }
          set(s => ({
            connected: false,
            reconnectCount: s.reconnectCount + 1,
          }));
          wsInstance = null;
          
          reconnectTimer = setTimeout(() => {
            reconnectDelay = Math.min(reconnectDelay * 2, 8000);
            get().connectWebSocket();
          }, reconnectDelay);
        };

        wsInstance.onerror = () => {
          if (wsInstance?.readyState === WebSocket.OPEN) {
            wsInstance.close();
          }
        };

      } catch (err) {
         reconnectTimer = setTimeout(() => {
           get().connectWebSocket();
         }, 3000);
      }
    },

    disconnectWebSocket: () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (pingIntervalId !== null) {
        clearInterval(pingIntervalId);
        pingIntervalId = null;
      }
      if (wsInstance) {
        wsInstance.onclose = null; // prevent auto-reconnect fallback
        wsInstance.close();
        wsInstance = null;
      }
      set({ connected: false });
    }
  };
});
