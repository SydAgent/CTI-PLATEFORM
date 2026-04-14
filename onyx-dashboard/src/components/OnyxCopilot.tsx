'use client';

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { usePathname } from 'next/navigation';
import { TerminalMessage } from './chat/TerminalMessage';
import { CommandInput } from './chat/CommandInput';
import { Activity, ShieldAlert } from 'lucide-react';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  tags?: string[];
  isStreaming?: boolean;
  isGuardrailBlock?: boolean;
  isQuotaBlock?: boolean;
}

export default function OnyxCopilot() {
  const [isOpen, setIsOpen] = useState(false);
  const pathname = usePathname();
  const [sessionId, setSessionId] = useState<string | null>(null);

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: "## ONYX COPILOT\n\nAwaiting contextual instructions. Synchronized with live threat feeds.",
      tags: ['SYSTEM', 'READY']
    }
  ]);
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isLoading, isOpen, scrollToBottom]);

  const handleSendMessage = async (content: string) => {
    // Abort any in-flight stream
    if (abortRef.current) {
      abortRef.current.abort();
    }
    const controller = new AbortController();
    abortRef.current = controller;

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      role: 'user',
      content,
    };

    const aiMessageId = (Date.now() + 1).toString();

    setMessages(prev => [...prev, userMessage]);
    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE}/api/v1/agent/chat/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: content,
          session_id: sessionId,
          context: { current_page: pathname },
        }),
        signal: controller.signal,
      });

      // ── Handle 403 Guardrail Block ──────────────────────────────
      if (response.status === 403) {
        let errorMsg = 'Security policy violation detected.';
        try {
          const errBody = await response.json();
          errorMsg = errBody?.detail?.error || errBody?.error || errorMsg;
        } catch { /* use default */ }

        const blockedMessage: ChatMessage = {
          id: aiMessageId,
          role: 'assistant',
          content: `**⛔ GUARDRAIL BLOCK**\n\n\`${errorMsg}\`\n\nYour query was rejected by the ONYX security policy engine. Rephrase your request within CTI/OSINT scope.`,
          tags: ['BLOCKED', 'GUARDRAIL'],
          isGuardrailBlock: true,
        };
        setMessages(prev => [...prev, blockedMessage]);
        setIsLoading(false);
        return;
      }

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      // ── Capture session ID from headers ─────────────────────────
      const newSessionId = response.headers.get('X-Session-Id');
      if (newSessionId) {
        setSessionId(newSessionId);
      }

      // ── SSE Stream Processing ───────────────────────────────────
      const reader = response.body?.getReader();
      if (!reader) throw new Error('No response body');

      const decoder = new TextDecoder();
      let accumulatedText = '';

      // Create placeholder streaming message
      setMessages(prev => [...prev, {
        id: aiMessageId,
        role: 'assistant',
        content: '',
        tags: [],
        isStreaming: true,
      }]);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const payload = line.slice(6).trim();

          if (payload === '[DONE]') continue;

          try {
            const parsed = JSON.parse(payload);

            if (parsed.error) {
              // Error event from backend (output guardrail, etc.)
              if (parsed.error === 'API_QUOTA_EXCEEDED') {
                setMessages(prev => prev.map(m =>
                  m.id === aiMessageId
                    ? { ...m, isQuotaBlock: true, tags: ['QUOTA_EXHAUSTED'] }
                    : m
                ));
              } else {
                accumulatedText += `\n\n**⚠️ ${parsed.error}**`;
                setMessages(prev => prev.map(m =>
                  m.id === aiMessageId
                    ? { ...m, content: accumulatedText, tags: ['WARNING'] }
                    : m
                ));
              }
              continue;
            }

            if (parsed.text) {
              accumulatedText += parsed.text;
              setMessages(prev => prev.map(m =>
                m.id === aiMessageId
                  ? { ...m, content: accumulatedText }
                  : m
              ));
            }
          } catch {
            // Non-JSON line — skip
          }
        }
      }

      // Finalize streaming message
      setMessages(prev => prev.map(m =>
        m.id === aiMessageId
          ? { ...m, isStreaming: false }
          : m
      ));

    } catch (error: any) {
      if (error.name === 'AbortError') return;

      const errorMessage: ChatMessage = {
        id: aiMessageId,
        role: 'assistant',
        content: `**[TRANSACTION FAILURE]**\n\nAnalysis interrupted.\nReason: ${error.message}`,
        tags: ['CRITICAL', 'ERROR']
      };
      setMessages(prev => {
        // Replace streaming placeholder or append
        const exists = prev.some(m => m.id === aiMessageId);
        if (exists) {
          return prev.map(m => m.id === aiMessageId ? errorMessage : m);
        }
        return [...prev, errorMessage];
      });
    } finally {
      setIsLoading(false);
    }
  };

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <>
      {/* ── Chat Window ──────────────────────────────────────────────── */}
      {isOpen && (
        <div
          id="onyx-copilot-window"
          style={{
            position: 'fixed',
            bottom: 80,
            right: 20,
            width: 400,
            height: 500,
            zIndex: 9999,
            borderRadius: 10,
            overflow: 'hidden',
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
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: 56,
              padding: '16px 20px',
              background: 'linear-gradient(135deg, #0c1019 0%, #121828 100%)',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              zIndex: 2,
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
                  RAG Pipeline · Gemini 2.0 · Live
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

          {/* ── Chat Body ──────────────────────────────────── */}
          <div style={{
            position: 'absolute',
            top: 56,
            left: 0,
            width: 400,
            height: 372,
            maxHeight: 372,
            overflowY: 'auto',
            overflowX: 'hidden',
            padding: 16,
            wordBreak: 'break-word' as const,
          }}>
            {messages.map((msg) => (
              <div key={msg.id}>
                {msg.isGuardrailBlock ? (
                  <div
                    style={{
                      padding: '12px 16px',
                      borderRadius: 10,
                      background: 'rgba(255, 59, 92, 0.08)',
                      border: '1px solid rgba(255, 59, 92, 0.3)',
                      display: 'flex',
                      gap: 10,
                      alignItems: 'flex-start',
                      animation: 'copilotSlideUp 0.2s ease-out',
                    }}
                  >
                    <ShieldAlert size={18} style={{ color: '#ff3b5c', flexShrink: 0, marginTop: 2 }} />
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#ff3b5c', lineHeight: 1.6 }}>
                      <div style={{ fontWeight: 800, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '1px' }}>
                        ⛔ GUARDRAIL BLOCK
                      </div>
                      <div style={{ color: '#ff8a9e' }}>
                        Your query was rejected by the ONYX security policy engine. Rephrase within CTI/OSINT scope.
                      </div>
                    </div>
                  </div>
                ) : msg.isQuotaBlock ? (
                  <div
                    style={{
                      padding: '12px 16px',
                      borderRadius: 10,
                      background: 'rgba(255, 171, 0, 0.08)',
                      border: '1px solid rgba(255, 171, 0, 0.3)',
                      display: 'flex',
                      gap: 10,
                      alignItems: 'flex-start',
                      animation: 'copilotSlideUp 0.2s ease-out',
                    }}
                  >
                    <Activity size={18} style={{ color: '#ffab00', flexShrink: 0, marginTop: 2, animation: 'copilotPulse 2s ease-in-out infinite' }} />
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#ffab00', lineHeight: 1.6 }}>
                      <div style={{ fontWeight: 800, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '1px' }}>
                        ⚠️ SYSTEM ALERT
                      </div>
                      <div style={{ color: '#ffc107' }}>
                        Intelligence Feed Quota Exhausted. The upstream API gateway has throttled your billing account.
                      </div>
                    </div>
                  </div>
                ) : (
                  <TerminalMessage
                    role={msg.role}
                    content={msg.content}
                    tags={msg.tags}
                  />
                )}
              </div>
            ))}

            {isLoading && !messages.some(m => m.isStreaming) && (
              <div className="flex w-full gap-4 p-4 rounded-lg bg-[#0c1019]/80 border border-[#1a2236]">
                <div className="w-8 h-8 rounded bg-[#1a2236] border border-[#00f0ff]/30 flex items-center justify-center shrink-0">
                  <Activity size={16} className="text-[#00f0ff] animate-pulse" />
                </div>
                <div className="flex flex-col gap-2 w-full">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-[#00f0ff]">ONYX TACTICAL AI</span>
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded border bg-[#00f0ff]/10 text-[#00f0ff] border-[#00f0ff]/30 animate-pulse">
                      PROCESSING
                    </span>
                  </div>
                  <div className="text-sm font-mono text-[#8b95a8] animate-pulse">
                    Querying RAG pipeline...
                  </div>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* ── Input Area ─────────────────────────────────── */}
          <div style={{
            position: 'absolute',
            bottom: 0,
            left: 0,
            width: 400,
            height: 72,
            padding: '12px 16px',
            borderTop: '1px solid #1a2236',
            background: 'rgba(12, 16, 25, 0.95)',
            zIndex: 2,
          }}>
            <CommandInput onSend={handleSendMessage} isLoading={isLoading} />
            <div className="flex justify-between items-center mt-2 px-1">
               <span className="text-[9px] font-mono text-[#5a6478]">RAG + Guardrails Active</span>
               <span className="text-[9px] font-mono text-[#5a6478]">Gemini 2.0 Flash</span>
            </div>
          </div>
        </div>
      )}

      {/* ── Floating Action Button ────────────────────────────────── */}
      <button
        id="onyx-copilot-fab"
        onClick={() => setIsOpen((prev) => !prev)}
        aria-label="Open ONYX Copilot"
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
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'scale(1.1)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'scale(1)';
        }}
      >
        {isOpen ? (
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
