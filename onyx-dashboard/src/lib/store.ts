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
  
  setStats: (stats: DashboardStats | null) => void;
  setArmedIocs: (iocs: IOC[]) => void;
  setSelectedEventId: (id: string | null) => void;
  setSelectedActorId: (id: string | null) => void;
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

export const useOnyxStore = create<OnyxState>((set, get) => {

  const processBatch = () => {
    if (eventQueue.length === 0 && iocQueue.length === 0) {
      isRafScheduled = false;
      return;
    }

    set((state) => {
      // Keep feed fast: strictly up to 150 events
      const newEvents = [...eventQueue.reverse(), ...state.events].slice(0, 150);
      const newIocs = [...iocQueue.reverse(), ...state.armedIocs];
      
      const update = {
        events: newEvents,
        armedIocs: newIocs,
        liveIocCount: state.liveIocCount + iocQueue.length,
      };

      eventQueue = [];
      iocQueue = [];
      isRafScheduled = false;

      return update;
    });
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

    setStats: (stats) => set({ stats }),
    setArmedIocs: (iocs) => set({ armedIocs: iocs }),
    setSelectedEventId: (id) => set({ selectedEventId: id }),
    setSelectedActorId: (id) => set({ selectedActorId: id }),

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
          
          const pingInterval = setInterval(() => {
            if (wsInstance?.readyState === WebSocket.OPEN) {
              wsInstance.send(JSON.stringify({ type: 'ping' }));
            } else {
              clearInterval(pingInterval);
            }
          }, 15000);
          
          (wsInstance as any)._pingInterval = pingInterval;
        };

        wsInstance.onmessage = (event) => {
          try {
            // Security: Strictly enforce DOMPurify sanitization
            const rawMsg = JSON.parse(event.data);
            const msg = sanitizePayload(rawMsg);
            
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
                // Instantly append WS IOCs so IOC Explorer sees it automatically via the atomic state updater
                iocQueue.push(newEvent.data as unknown as IOC);
            }

            scheduleBatch();

          } catch (e) {
             console.error("WS Engine error parsing message:", e);
          }
        };

        wsInstance.onclose = () => {
          if ((wsInstance as any)?._pingInterval) {
            clearInterval((wsInstance as any)._pingInterval);
          }
          set({ connected: false });
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
      if (wsInstance) {
        wsInstance.onclose = null; // prevent auto-reconnect fallback
        if ((wsInstance as any)._pingInterval) {
          clearInterval((wsInstance as any)._pingInterval);
        }
        wsInstance.close();
        wsInstance = null;
      }
      set({ connected: false });
    }
  };
});
