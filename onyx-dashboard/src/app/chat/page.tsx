"use client";

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { TerminalMessage } from '@/components/chat/TerminalMessage';
import { CommandInput } from '@/components/chat/CommandInput';
import { ShieldAlert, Crosshair, Terminal, Activity } from 'lucide-react';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  isStreaming?: boolean;
  isGuardrailBlock?: boolean;
  isQuotaBlock?: boolean;
  tags?: string[];
}

export default function ChatPage() {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: "## TACTICAL AGENT ACTIVE\n\nAwaiting CTI queries, IOC analysis, or Dark Web intelligence requests.\n\n*Enter a query to engage contextual analysis.*",
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
    scrollToBottom();
  }, [messages, isLoading, scrollToBottom]);

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
      const response = await fetch(`${API_BASE}/api/v1/chat/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: content,
          session_id: sessionId,
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

  return (
    <div className="flex flex-col h-[calc(100vh-var(--header-height))] bg-[#06080f] text-[#e8ecf4]">
      {/* Header / Context Bar */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#1a2236] bg-[#0c1019]/80 backdrop-blur-md sticky top-0 z-10 shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-[#1a2236] border border-[#00f0ff]/30 shadow-[0_0_15px_rgba(0,240,255,0.15)] text-[#00f0ff]">
            <Terminal size={20} />
          </div>
          <div>
            <h1 className="text-lg font-bold uppercase tracking-wider text-[#e8ecf4]">Tactical Analysis Agent</h1>
            <p className="text-xs text-[#8b95a8] flex items-center gap-1 font-mono">
              <span className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse"></span>
              RAG PIPELINE · GUARDRAILS ACTIVE
            </p>
          </div>
        </div>

        <div className="hidden md:flex items-center gap-4 text-xs font-mono text-[#5a6478]">
          <div className="flex items-center gap-1"><ShieldAlert size={14} className="text-[#ff3b5c]" /> CTI MODE</div>
          <div className="flex items-center gap-1"><Crosshair size={14} className="text-[#00f0ff]" /> IOC PARSING ENABLED</div>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 overflow-y-auto p-4 md:p-6 lg:px-20 scroll-smooth">
        <div className="max-w-4xl mx-auto flex flex-col gap-2">
          {messages.map((msg) => (
            <div key={msg.id}>
              {msg.isGuardrailBlock ? (
                <div
                  className="flex gap-3 p-4 rounded-lg mb-4 border animate-pulse"
                  style={{
                    background: 'rgba(255, 59, 92, 0.06)',
                    borderColor: 'rgba(255, 59, 92, 0.3)',
                  }}
                >
                  <ShieldAlert size={20} className="text-[#ff3b5c] shrink-0 mt-1" />
                  <div className="font-mono text-sm">
                    <div className="font-bold text-[#ff3b5c] uppercase tracking-wider mb-1">
                      ⛔ GUARDRAIL BLOCK
                    </div>
                    <div className="text-[#ff8a9e] leading-relaxed">
                      Your query was rejected by the ONYX security policy engine.
                      Rephrase your request within CTI/OSINT scope.
                    </div>
                  </div>
                </div>
              ) : msg.isQuotaBlock ? (
                <div
                  className="flex gap-3 p-4 rounded-lg mb-4 border animate-pulse"
                  style={{
                    background: 'rgba(255, 171, 0, 0.06)',
                    borderColor: 'rgba(255, 171, 0, 0.3)',
                  }}
                >
                  <Activity size={20} className="text-[#ffab00] shrink-0 mt-1" />
                  <div className="font-mono text-sm">
                    <div className="font-bold text-[#ffab00] uppercase tracking-wider mb-1">
                      ⚠️ SYSTEM ALERT
                    </div>
                    <div className="text-[#ffc107] leading-relaxed">
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
            <div className="flex w-full gap-4 p-4 rounded-lg bg-[#0c1019]/80 border border-[#1a2236] max-w-4xl mx-auto">
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
      </div>

      {/* Input Area */}
      <div className="p-4 md:p-6 lg:px-20 border-t border-[#1a2236] bg-[#0c1019]/90 backdrop-blur-md shrink-0">
        <div className="max-w-4xl mx-auto">
          <CommandInput onSend={handleSendMessage} isLoading={isLoading} />
          <div className="flex justify-between items-center mt-2 px-2">
             <span className="text-[10px] font-mono text-[#5a6478]">ONYX Protocol // Restricted Access // Guardrails Active</span>
             <span className="text-[10px] font-mono text-[#5a6478]">Gemini 2.0 Flash · RAG Pipeline</span>
          </div>
        </div>
      </div>
    </div>
  );
}
