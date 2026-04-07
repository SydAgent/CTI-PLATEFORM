import React, { useState, useRef, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import jsPDF from 'jspdf';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface Message {
  role: 'user' | 'agent';
  content: string;
  isReport?: boolean;
}

export default function AgenticCopilot() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    { role: 'agent', content: "### OMNI-AGENT SYSTEM READY\nJe suis **SecGPT v2**, l'intelligence omnisciente d'ONYX. Je suis connecté à vos flux de données en temps réel en mode `STREAMING`. L'Usine à rapports est prête. Comment puis-je assister votre investigation ?" }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [typing, setTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isOpen, typing]);

  const handleStream = async (url: string, body?: any, isReport: boolean = false) => {
    setLoading(true);
    setTyping(true);
    
    // Add empty agent message that we will populate
    setMessages(prev => [...prev, { role: 'agent', content: "", isReport }]);
    
    try {
      const fetchUrl = url;
      const res = await fetch(fetchUrl, {
        method: body ? 'POST' : 'GET',
        headers: body ? { 'Content-Type': 'application/json' } : {},
        body: body ? JSON.stringify(body) : undefined
      });
      
      setTyping(false);

      const reader = res.body?.getReader();
      const decoder = new TextDecoder("utf-8");
      
      let fullText = "";

      if (reader) {
        let buffer = "";
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n\n");
          
          buffer = lines.pop() || "";
          
          for (const line of lines) {
            if (line.trim().startsWith("data: ")) {
              try {
                const data = JSON.parse(line.trim().substring(6));
                if (data.text !== undefined) {
                  fullText += data.text;
                  setMessages(prev => {
                    const newMessages = [...prev];
                    newMessages[newMessages.length - 1].content = fullText;
                    return newMessages;
                  });
                }
              } catch (e) {
                // Ignore parse errors on incomplete chunks
              }
            }
          }
        }
      }
    } catch (e) {
      setMessages(prev => {
        const newMessages = [...prev];
        newMessages[newMessages.length - 1].content = "⚠️ **CRITICAL ERROR**: Flux streaming interrompu.";
        return newMessages;
      });
    } finally {
      setLoading(false);
      setTyping(false);
    }
  };

  const handleSend = async (textOverride?: string) => {
    const userMsg = textOverride || input.trim();
    if (!userMsg) return;
    
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    
    if (userMsg.toLowerCase().includes("rapport")) {
      await handleStream(`/api/v1/agent/report/stream?target=MenaceGlobale`, undefined, true);
    } else {
      await handleStream(`/api/v1/agent/chat/stream`, { message: userMsg, context: { platform: "ONYX-CTI", mode: "Elite" } });
    }
  };

  const exportPDF = (content: string) => {
    const doc = new jsPDF();
    doc.setFont("helvetica");
    doc.setFontSize(16);
    doc.text("ONYX EXPERT REPORT (AUTO-GENERATED)", 14, 20);
    doc.setFontSize(10);
    const splitText = doc.splitTextToSize(content, 180);
    doc.text(splitText, 14, 30);
    doc.save("ONYX_Expert_Report.pdf");
  };

  if (!isOpen) {
    return (
      <div 
        onClick={() => setIsOpen(true)}
        className="copilot-pill animate-pulse"
        style={{ 
          position: 'fixed', bottom: 32, right: 32, padding: '12px 24px', 
          borderRadius: 99, background: 'linear-gradient(135deg, #a855f7, #00f0ff)', 
          color: '#000', fontWeight: 800, fontSize: 13, cursor: 'pointer',
          boxShadow: '0 10px 40px rgba(168,85,247,0.5)', zIndex: 9999,
          display: 'flex', alignItems: 'center', gap: 10, letterSpacing: '1px'
        }}
      >
        <span>🧠</span> SECGPT OMNI-AGENT (LIVE)
      </div>
    );
  }

  return (
    <div className="animate-in" style={{ 
      position: 'fixed', bottom: 32, right: 32, width: 500, height: 750, 
      background: 'rgba(5, 8, 15, 0.98)', backdropFilter: 'blur(30px)', 
      border: '1px solid rgba(0, 240, 255, 0.3)', borderRadius: 20, 
      display: 'flex', flexDirection: 'column', overflow: 'hidden', zIndex: 9999,
      boxShadow: '0 25px 60px rgba(0,0,0,0.9), 0 0 20px rgba(0,240,255,0.1)'
    }}>
      {/* Header — Terminal Style */}
      <div style={{ padding: '20px 24px', borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'linear-gradient(to right, #0a0f1a, #05080f)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div className="pulse-live" style={{ width: 10, height: 10, background: '#a855f7', boxShadow: '0 0 10px #a855f7' }}></div>
          <div>
            <div style={{ fontFamily: 'monospace', fontWeight: 900, fontSize: 13, color: '#fff', letterSpacing: '2px' }}>ONYX <span style={{ color: '#00f0ff' }}>SecGPT v2</span></div>
            <div style={{ fontSize: 9, color: '#6b7280', textTransform: 'uppercase', marginTop: 2 }}>Streaming Engine: Active</div>
          </div>
        </div>
        <button onClick={() => setIsOpen(false)} style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, width: 32, height: 32, color: '#6b7280', fontSize: 18, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>×</button>
      </div>

      {/* Message Area */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '24px', display: 'flex', flexDirection: 'column', gap: 20, scrollbarWidth: 'thin' }}>
        {messages.map((m, i) => (
          <div key={i} style={{ alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start', maxWidth: '95%' }}>
            <div style={{ fontSize: 9, color: '#4b5563', marginBottom: 6, textAlign: m.role === 'user' ? 'right' : 'left', letterSpacing: '1px', fontWeight: 800 }}>
              {m.role === 'user' ? '► ANALYSTE' : '◄ SECGPT CORE'}
            </div>
            <div style={{ 
              background: m.role === 'user' ? 'linear-gradient(135deg, rgba(0,240,255,0.12), rgba(0,240,255,0.02))' : 'rgba(255,255,255,0.01)', 
              border: m.role === 'user' ? '1px solid rgba(0,240,255,0.25)' : '1px solid rgba(255,255,255,0.06)',
              padding: '16px 20px', borderRadius: 16, borderBottomRightRadius: m.role === 'user' ? 2 : 16, borderTopLeftRadius: m.role === 'agent' ? 2 : 16,
              color: '#e5e7eb', fontSize: 13, lineHeight: 1.6, boxShadow: m.role === 'user' ? '0 4px 15px rgba(0,240,255,0.05)' : 'none'
            }}>
              <ReactMarkdown 
                remarkPlugins={[remarkGfm]}
                components={{
                  p: ({node, ...props}) => <p style={{ margin: '0 0 12px 0' }} {...props} />,
                  h3: ({node, ...props}) => <h3 style={{ borderLeft: '3px solid #a855f7', paddingLeft: 12, margin: '16px 0 10px 0', fontSize: 14, color: '#fff', fontWeight: 800, textTransform: 'uppercase' }} {...props} />,
                  ul: ({node, ...props}) => <ul style={{ paddingLeft: 20, marginBottom: 12, color: '#9ca3af' }} {...props} />,
                  li: ({node, ...props}) => <li style={{ marginBottom: 6 }} {...props} />,
                  table: ({node, ...props}) => <div style={{ overflowX: 'auto', margin: '12px 0' }}><table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }} {...props} /></div>,
                  th: ({node, ...props}) => <th style={{ borderBottom: '1px solid #374151', padding: '8px 10px', textAlign: 'left', color: '#00f0ff' }} {...props} />,
                  td: ({node, ...props}) => <td style={{ borderBottom: '1px solid #1f2937', padding: '8px 10px' }} {...props} />,
                  code: ({node, ...props}) => <code style={{ background: '#111', padding: '2px 6px', borderRadius: 4, color: '#f87171', fontFamily: 'monospace', fontSize: 11 }} {...props} />
                }}
              >
                {m.content}
              </ReactMarkdown>
              
              {m.isReport && !loading && (
                <button 
                  onClick={() => exportPDF(m.content)}
                  style={{ marginTop: 12, padding: '8px 16px', background: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: 8, cursor: 'pointer', fontSize: 11, fontWeight: 'bold' }}
                >
                  📥 EXPORT PDF (8-SECTIONS)
                </button>
              )}
            </div>
          </div>
        ))}
        {typing && (
          <div style={{ display: 'flex', gap: 6, padding: '10px 0' }}>
            <span className="dot-pulse" style={{ width: 4, height: 4, background: '#00f0ff', borderRadius: '50%', animation: 'pulse 1.5s infinite 0s' }}></span>
            <span className="dot-pulse" style={{ width: 4, height: 4, background: '#00f0ff', borderRadius: '50%', animation: 'pulse 1.5s infinite 0.3s' }}></span>
            <span className="dot-pulse" style={{ width: 4, height: 4, background: '#00f0ff', borderRadius: '50%', animation: 'pulse 1.5s infinite 0.6s' }}></span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Actions Panel */}
      <div style={{ padding: '12px 24px', display: 'flex', gap: 8, flexWrap: 'wrap', background: 'rgba(0,0,0,0.2)', borderTop: '1px solid rgba(255,255,255,0.03)' }}>
        <button disabled={loading} onClick={() => handleSend("Statut des menaces ?")} style={{ fontSize: 9, padding: '6px 12px', background: '#0a101f', border: '1px solid #1f2937', borderRadius: 99, color: '#6b7280', cursor: 'pointer' }}>STATUT LIVE</button>
        <button disabled={loading} onClick={() => handleSend("Isole l'IP 185.220.101.45")} style={{ fontSize: 9, padding: '6px 12px', background: '#0a101f', border: '1px solid #1f2937', borderRadius: 99, color: '#6b7280', cursor: 'pointer' }}>REMEDIATION</button>
        <button disabled={loading} onClick={() => handleSend("Génère un rapport pour Volt Typhoon")} style={{ fontSize: 9, padding: '6px 12px', background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.4)', borderRadius: 99, color: '#a855f7', cursor: 'pointer', fontWeight: 'bold' }}>⚡ GEN-REPORT (8-SEC)</button>
      </div>

      {/* Input Area */}
      <div style={{ padding: '24px', background: '#05080f', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
          <input 
            type="text" 
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            placeholder="Interrogez l'intelligence ONYX..."
            style={{ 
              width: '100%', background: '#0a0f1a', border: '1px solid #1e293b', 
              borderRadius: 12, padding: '16px 50px 16px 20px', color: '#fff', 
              fontSize: 13, outline: 'none', transition: 'border-color 0.2s',
              boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.5)'
            }}
            onFocus={(e) => e.target.style.borderColor = '#00f0ff'}
            onBlur={(e) => e.target.style.borderColor = '#1e293b'}
            disabled={loading}
          />
          <button 
            onClick={() => handleSend()}
            disabled={loading}
            style={{ 
              position: 'absolute', right: 12, width: 34, height: 34, 
              background: loading ? '#333' : 'linear-gradient(135deg, #a855f7, #00f0ff)', 
              border: 'none', borderRadius: 8, color: '#000', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold'
            }}
          >
            ➤
          </button>
        </div>
      </div>
    </div>
  );
}
