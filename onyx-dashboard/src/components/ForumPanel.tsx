'use client';

import React, { useEffect, useState, useCallback } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface Reply {
  id: string;
  content: string;
  author: string;
  created_at: string;
}

interface Thread {
  id: string;
  title: string;
  content: string;
  author: string;
  tags: string[];
  created_at: string;
  replies: Reply[];
  pinned: boolean;
}

export default function ForumPanel() {
  const [threads, setThreads] = useState<Thread[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<string>('CONNECTING');
  const [selectedThread, setSelectedThread] = useState<string | null>(null);
  const [replyText, setReplyText] = useState('');
  const [replyAuthor, setReplyAuthor] = useState('Analyst');
  const [showNewThread, setShowNewThread] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newContent, setNewContent] = useState('');
  const [newAuthor, setNewAuthor] = useState('Analyst');
  const [newTags, setNewTags] = useState('');

  const fetchThreads = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/forum/threads`);
      const data = await res.json();
      setThreads(data.threads || []);
      setStatus(data.status || 'ONLINE');
      setLoading(false);
    } catch {
      setStatus('OFFLINE');
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchThreads();
    const interval = setInterval(fetchThreads, 15_000);
    return () => clearInterval(interval);
  }, [fetchThreads]);

  const handleCreateThread = async () => {
    if (!newTitle.trim() || !newContent.trim()) return;
    try {
      await fetch(`${API}/api/v1/forum/threads`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newTitle,
          content: newContent,
          author: newAuthor || 'Analyst',
          tags: newTags.split(',').map(t => t.trim()).filter(Boolean),
        }),
      });
      setNewTitle('');
      setNewContent('');
      setNewTags('');
      setShowNewThread(false);
      await fetchThreads();
    } catch {}
  };

  const handleReply = async (threadId: string) => {
    if (!replyText.trim()) return;
    try {
      await fetch(`${API}/api/v1/forum/threads/${threadId}/replies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: replyText, author: replyAuthor || 'Analyst' }),
      });
      setReplyText('');
      await fetchThreads();
    } catch {}
  };

  const selectedData = threads.find(t => t.id === selectedThread);

  const statusColor = status === 'ONLINE' ? '#22c55e' : status === 'CONNECTING' ? '#f59e0b' : '#ef4444';
  const inputStyle: React.CSSProperties = {
    width: '100%',
    background: '#0a0a0a',
    border: '1px solid #1f2937',
    borderRadius: 8,
    padding: '10px 14px',
    color: '#e5e7eb',
    fontSize: 12,
    fontFamily: 'monospace',
    outline: 'none',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: 22, fontWeight: 800, background: 'linear-gradient(135deg, #00eeff, #a855f7)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', marginBottom: 4 }}>
            💬 Analyst Collaboration Forum
          </h2>
          <p style={{ fontSize: 11, color: '#4b5563', fontFamily: 'monospace' }}>
            Threat discussions · IOC sharing · Incident coordination
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, fontFamily: 'monospace', color: statusColor, border: `1px solid ${statusColor}44`, padding: '4px 12px', borderRadius: 99 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: statusColor, display: 'inline-block', boxShadow: `0 0 8px ${statusColor}` }} />
            {status}
          </div>
          <button onClick={() => setShowNewThread(true)} style={{ padding: '8px 18px', background: 'rgba(0,238,255,0.1)', border: '1px solid rgba(0,238,255,0.4)', borderRadius: 8, color: '#00eeff', fontSize: 12, cursor: 'pointer', fontWeight: 700 }}>
            + New Thread
          </button>
        </div>
      </div>

      {/* New Thread Form */}
      {showNewThread && (
        <div style={{ background: '#0a0f1a', borderRadius: 12, border: '1px solid #1e293b', padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#00eeff' }}>Create New Thread</div>
          <input placeholder="Thread title..." value={newTitle} onChange={e => setNewTitle(e.target.value)} style={inputStyle} />
          <textarea placeholder="Write your analysis or question..." value={newContent} onChange={e => setNewContent(e.target.value)} rows={4} style={{ ...inputStyle, resize: 'vertical' }} />
          <div style={{ display: 'flex', gap: 10 }}>
            <input placeholder="Author name" value={newAuthor} onChange={e => setNewAuthor(e.target.value)} style={{ ...inputStyle, flex: 1 }} />
            <input placeholder="Tags (comma-separated)" value={newTags} onChange={e => setNewTags(e.target.value)} style={{ ...inputStyle, flex: 1 }} />
          </div>
          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
            <button onClick={() => setShowNewThread(false)} style={{ padding: '8px 16px', background: 'transparent', border: '1px solid #374151', borderRadius: 8, color: '#6b7280', cursor: 'pointer', fontSize: 12 }}>Cancel</button>
            <button onClick={handleCreateThread} style={{ padding: '8px 16px', background: 'rgba(0,238,255,0.15)', border: '1px solid rgba(0,238,255,0.5)', borderRadius: 8, color: '#00eeff', cursor: 'pointer', fontSize: 12, fontWeight: 700 }}>Publish</button>
          </div>
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: '#4b5563', fontFamily: 'monospace', fontSize: 12 }}>
          Connecting to Forum service...
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 16 }}>
          {/* Thread List */}
          <div style={{ flex: selectedThread ? '0 0 380px' : 1, display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 'calc(100vh - 240px)', overflowY: 'auto' }}>
            {threads.map(thread => (
              <div
                key={thread.id}
                onClick={() => setSelectedThread(thread.id === selectedThread ? null : thread.id)}
                style={{
                  background: thread.id === selectedThread ? '#111827' : '#0a0f1a',
                  borderRadius: 10,
                  border: `1px solid ${thread.id === selectedThread ? '#00eeff33' : '#1e293b'}`,
                  padding: 16,
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  borderLeft: thread.pinned ? '3px solid #ef4444' : `3px solid transparent`,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                  <div style={{ fontWeight: 600, fontSize: 13, color: '#e5e7eb', lineHeight: 1.4, flex: 1 }}>{thread.title}</div>
                  {thread.pinned && <span style={{ fontSize: 8, padding: '2px 6px', borderRadius: 4, background: 'rgba(239,68,68,0.15)', color: '#ef4444', fontWeight: 700, marginLeft: 8, whiteSpace: 'nowrap' }}>PINNED</span>}
                </div>
                <div style={{ fontSize: 11, color: '#6b7280', fontFamily: 'monospace', marginBottom: 8 }}>
                  {thread.author} · {new Date(thread.created_at).toLocaleDateString()} · {thread.replies.length} replies
                </div>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {thread.tags.map((tag, i) => (
                    <span key={i} style={{ fontSize: 9, padding: '2px 8px', borderRadius: 99, background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.3)', color: '#a855f7' }}>
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Thread Detail */}
          {selectedData && (
            <div style={{ flex: 1, background: '#0a0f1a', borderRadius: 12, border: '1px solid #1e293b', padding: 20, display: 'flex', flexDirection: 'column', gap: 16, maxHeight: 'calc(100vh - 240px)', overflowY: 'auto' }}>
              <div>
                <div style={{ fontSize: 16, fontWeight: 700, color: '#e5e7eb', marginBottom: 8 }}>{selectedData.title}</div>
                <div style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace', marginBottom: 12 }}>
                  By {selectedData.author} · {new Date(selectedData.created_at).toLocaleString()}
                </div>
                <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.7, padding: 16, background: '#111827', borderRadius: 8, border: '1px solid #1f2937' }}>
                  {selectedData.content}
                </div>
              </div>

              {/* Replies */}
              <div style={{ borderTop: '1px solid #1f2937', paddingTop: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  {selectedData.replies.length} Responses
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
                  {selectedData.replies.map(reply => (
                    <div key={reply.id} style={{ padding: 12, background: '#0f172a', borderRadius: 8, borderLeft: '3px solid #334155' }}>
                      <div style={{ fontSize: 12, color: '#e5e7eb', lineHeight: 1.6, marginBottom: 8 }}>{reply.content}</div>
                      <div style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace' }}>— {reply.author} · {new Date(reply.created_at).toLocaleString()}</div>
                    </div>
                  ))}
                </div>

                {/* Reply Input */}
                <div style={{ display: 'flex', gap: 8 }}>
                  <input placeholder="Author" value={replyAuthor} onChange={e => setReplyAuthor(e.target.value)} style={{ ...inputStyle, width: 120, flex: 'none' }} />
                  <input
                    placeholder="Write your reply..."
                    value={replyText}
                    onChange={e => setReplyText(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') handleReply(selectedData.id); }}
                    style={{ ...inputStyle, flex: 1 }}
                  />
                  <button onClick={() => handleReply(selectedData.id)} style={{ padding: '10px 18px', background: 'rgba(0,238,255,0.15)', border: '1px solid rgba(0,238,255,0.4)', borderRadius: 8, color: '#00eeff', cursor: 'pointer', fontSize: 12, fontWeight: 700, whiteSpace: 'nowrap' }}>
                    Send
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
