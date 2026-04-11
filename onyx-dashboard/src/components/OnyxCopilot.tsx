'use client';

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { usePathname } from 'next/navigation';

/**
 * OnyxCopilot — Deep Chat–powered floating chatbot widget.
 *
 * Renders a Floating Action Button (FAB) in the bottom-right corner.
 * Clicking it opens a <DeepChat /> window connected to the ONYX backend
 * via the existing SSE streaming endpoint (/api/v1/agent/chat/stream).
 *
 * deep-chat is a Web Component, so we dynamically import it to avoid
 * Next.js SSR issues and interact with it via ref + vanilla DOM attrs.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function OnyxCopilot() {
  const [isOpen, setIsOpen] = useState(false);
  const [isLoaded, setIsLoaded] = useState(false);
  const chatRef = useRef<any>(null);
  const pathname = usePathname();

  // ── Dynamic import of the deep-chat Web Component ──────────────────────
  // deep-chat registers a <deep-chat> custom element on the window.
  // We import it once on mount (client-side only).
  useEffect(() => {
    let cancelled = false;
    import('deep-chat-react').then(() => {
      if (!cancelled) setIsLoaded(true);
    });
    return () => { cancelled = true; };
  }, []);

  // ── Configure the <deep-chat> element once the ref is available ────────
  useEffect(() => {
    // Re-run whenever the chat opens, the component loads, or the page changes
    const el = chatRef.current;
    if (!el || !isOpen) return;

    // -- Connect: native deep-chat SSE stream mode --------------------------
    // The backend (POST /api/v1/agent/chat/stream) now emits compliant SSE:
    //   data: {"text": "word "}\n\n
    // So we can use deep-chat's built-in stream support directly.
    el.connect = {
      url: `${API_BASE}/api/v1/agent/chat/stream`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      stream: true,
    };

    // -- Context-Awareness: inject current page into every request ----------
    // deep-chat calls this function before sending each request.
    // We add "current_page" so the backend/LLM knows what the analyst is viewing.
    el.requestInterceptor = (details: any) => {
      const body = details.body;
      if (body && typeof body === 'object') {
        body.current_page = pathname || '/';
      }
      return details;
    };

    // -- Intro message ────────────────────────────────────────────────────
    el.introMessage = {
      text: '🔒 **ONYX Copilot** connecté.\nInterrogez vos flux Threat Intel en temps réel.',
    };

    // -- Styling: deep cyber dark theme ──────────────────────────────────
    el.style.cssText = `
      width: 100%;
      height: 100%;
      border: none;
      border-radius: 0;
      font-family: 'Inter', sans-serif;
      --deep-chat-bg: #0a0f1a;
    `;

    el.chatStyle = {
      backgroundColor: '#0a0f1a',
    };

    el.messageStyles = {
      default: {
        shared: {
          bubble: {
            backgroundColor: 'rgba(255,255,255,0.04)',
            color: '#e8ecf4',
            borderRadius: '14px',
            fontSize: '13px',
            lineHeight: '1.6',
            padding: '14px 18px',
            border: '1px solid rgba(255,255,255,0.06)',
          },
        },
        user: {
          bubble: {
            backgroundColor: 'rgba(0, 240, 255, 0.1)',
            border: '1px solid rgba(0, 240, 255, 0.25)',
            color: '#e8ecf4',
            borderBottomRightRadius: '4px',
          },
        },
        ai: {
          bubble: {
            backgroundColor: 'rgba(168, 85, 247, 0.08)',
            border: '1px solid rgba(168, 85, 247, 0.2)',
            color: '#e8ecf4',
            borderBottomLeftRadius: '4px',
          },
        },
      },
      loading: {
        bubble: {
          backgroundColor: 'rgba(255,255,255,0.03)',
          color: '#00f0ff',
          fontSize: '12px',
        },
      },
    };

    el.textInput = {
      placeholder: { text: 'Interrogez ONYX Copilot...' },
      styles: {
        container: {
          backgroundColor: '#121828',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: '12px',
          color: '#e8ecf4',
          boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.4)',
        },
        text: {
          color: '#e8ecf4',
          fontSize: '13px',
        },
        focus: {
          border: '1px solid rgba(0, 240, 255, 0.5)',
        },
      },
    };

    el.submitButtonStyles = {
      submit: {
        container: {
          default: {
            backgroundColor: '#a855f7',
            borderRadius: '8px',
          },
          hover: {
            backgroundColor: '#9333ea',
          },
        },
        svg: {
          content:
            '<?xml version="1.0" encoding="utf-8"?><svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" fill="white"/></svg>',
          styles: {
            default: {
              filter: 'brightness(1)',
            },
          },
        },
      },
      loading: {
        container: {
          default: {
            backgroundColor: '#374151',
            borderRadius: '8px',
          },
        },
        svg: {
          styles: {
            default: {
              filter: 'brightness(0.5)',
            },
          },
        },
      },
    };

    el.avatars = {
      ai: {
        src: '',
        styles: {
          avatar: { display: 'none' },
        },
      },
      user: {
        src: '',
        styles: {
          avatar: { display: 'none' },
        },
      },
    };

    el.names = {
      ai: { text: 'ONYX COPILOT' },
      user: { text: 'ANALYSTE' },
    };

  }, [isOpen, isLoaded, pathname]);

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <>
      {/* ── Chat Window ──────────────────────────────────────────────── */}
      {isOpen && (
        <div
          id="onyx-copilot-window"
          style={{
            position: 'fixed',
            bottom: 100,
            right: 28,
            width: 420,
            height: 600,
            zIndex: 10000,
            borderRadius: 20,
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column',
            background: '#0a0f1a',
            border: '1px solid rgba(0, 240, 255, 0.2)',
            boxShadow:
              '0 25px 80px rgba(0,0,0,0.8), 0 0 30px rgba(0, 240, 255, 0.08)',
            animation: 'copilotSlideUp 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards',
          }}
        >
          {/* ── Header ──────────────────────────────────────────── */}
          <div
            style={{
              padding: '16px 20px',
              background: 'linear-gradient(135deg, #0c1019 0%, #121828 100%)',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexShrink: 0,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: '50%',
                  background: '#00ff88',
                  boxShadow: '0 0 8px #00ff88',
                  animation: 'copilotPulse 2s ease-in-out infinite',
                }}
              />
              <div>
                <div
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontWeight: 800,
                    fontSize: 13,
                    color: '#fff',
                    letterSpacing: '1.5px',
                  }}
                >
                  ONYX{' '}
                  <span style={{ color: '#00f0ff' }}>COPILOT</span>
                </div>
                <div
                  style={{
                    fontSize: 9,
                    color: '#5a6478',
                    textTransform: 'uppercase',
                    letterSpacing: '1px',
                    marginTop: 2,
                  }}
                >
                  Deep Chat · LLM Bridge · Live
                </div>
              </div>
            </div>
            <button
              id="onyx-copilot-close"
              onClick={() => setIsOpen(false)}
              style={{
                background: 'transparent',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 8,
                width: 30,
                height: 30,
                color: '#5a6478',
                fontSize: 16,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'rgba(255,59,92,0.5)';
                e.currentTarget.style.color = '#ff3b5c';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)';
                e.currentTarget.style.color = '#5a6478';
              }}
            >
              ×
            </button>
          </div>

          {/* ── Deep Chat Body ──────────────────────────────────── */}
          <div style={{ flex: 1, overflow: 'hidden' }}>
            {isLoaded ? (
              // @ts-ignore — deep-chat is a Web Component, TS doesn't know it
              <deep-chat
                ref={chatRef}
                style={{ width: '100%', height: '100%', border: 'none' }}
              />
            ) : (
              <div
                style={{
                  height: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#5a6478',
                  fontSize: 12,
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                Chargement du moteur LLM…
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Floating Action Button ────────────────────────────────── */}
      <button
        id="onyx-copilot-fab"
        onClick={() => setIsOpen((prev) => !prev)}
        aria-label="Ouvrir ONYX Copilot"
        style={{
          position: 'fixed',
          bottom: 28,
          right: 28,
          width: 58,
          height: 58,
          borderRadius: '50%',
          border: 'none',
          cursor: 'pointer',
          zIndex: 10001,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: isOpen
            ? 'linear-gradient(135deg, #ff3b5c, #ff6b35)'
            : 'linear-gradient(135deg, #a855f7, #00f0ff)',
          boxShadow: isOpen
            ? '0 8px 32px rgba(255, 59, 92, 0.5)'
            : '0 8px 32px rgba(168, 85, 247, 0.5)',
          transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
          transform: isOpen ? 'rotate(0deg)' : 'rotate(0deg)',
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'scale(1.1)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'scale(1)';
        }}
      >
        {isOpen ? (
          // Close icon (X)
          <svg
            width="22"
            height="22"
            viewBox="0 0 24 24"
            fill="none"
            stroke="white"
            strokeWidth="2.5"
            strokeLinecap="round"
          >
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        ) : (
          // Robot icon
          <svg
            width="26"
            height="26"
            viewBox="0 0 24 24"
            fill="none"
            stroke="white"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <rect x="3" y="11" width="18" height="10" rx="2" />
            <circle cx="12" cy="5" r="2" />
            <line x1="12" y1="7" x2="12" y2="11" />
            <line x1="8" y1="16" x2="8" y2="16" />
            <line x1="16" y1="16" x2="16" y2="16" />
            <circle cx="8" cy="16" r="1" fill="white" />
            <circle cx="16" cy="16" r="1" fill="white" />
          </svg>
        )}
      </button>

      {/* ── Keyframes injected via <style> ────────────────────────── */}
      <style jsx global>{`
        @keyframes copilotSlideUp {
          from {
            opacity: 0;
            transform: translateY(20px) scale(0.95);
          }
          to {
            opacity: 1;
            transform: translateY(0) scale(1);
          }
        }
        @keyframes copilotPulse {
          0%, 100% {
            box-shadow: 0 0 4px #00ff88, 0 0 8px rgba(0, 255, 136, 0.3);
          }
          50% {
            box-shadow: 0 0 8px #00ff88, 0 0 20px rgba(0, 255, 136, 0.5);
          }
        }
      `}</style>
    </>
  );
}
