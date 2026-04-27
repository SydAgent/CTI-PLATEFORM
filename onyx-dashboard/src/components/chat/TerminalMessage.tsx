"use client";

import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Copy, Check, ShieldAlert, User, Cpu } from 'lucide-react';
import { cn } from '@/lib/utils';
import { motion } from 'framer-motion';

interface TerminalMessageProps {
  role: 'user' | 'assistant';
  content: string;
  tags?: string[];
}

export function TerminalMessage({ role, content, tags }: TerminalMessageProps) {
  const isAssistant = role === 'assistant';

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className={cn(
        "flex w-full gap-4 p-4 rounded-lg mb-4 border",
        isAssistant 
          ? "bg-[#0c1019]/80 border-[#1a2236]" 
          : "bg-[#121828]/50 border-transparent ml-auto max-w-[85%]"
      )}
    >
      {/* Avatar */}
      <div className="flex-shrink-0 mt-1">
        {isAssistant ? (
          <div className="w-8 h-8 rounded bg-[#1a2236] border border-[#00f0ff]/30 flex items-center justify-center shadow-[0_0_10px_rgba(0,240,255,0.1)]">
            <Cpu size={16} className="text-[#00f0ff]" />
          </div>
        ) : (
          <div className="w-8 h-8 rounded bg-[#1a2236] flex items-center justify-center">
            <User size={16} className="text-[#8b95a8]" />
          </div>
        )}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-x-hidden overflow-y-visible" style={{ wordBreak: 'break-word' }}>
        <div className="flex items-center gap-2 mb-2">
          <span className={cn("text-xs font-bold uppercase tracking-wider", isAssistant ? "text-[#00f0ff]" : "text-[#8b95a8]")}>
            {isAssistant ? "ONYX TACTICAL AI" : "ANALYST"}
          </span>
          {tags && tags.length > 0 && (
            <div className="flex gap-2 ml-2">
              {tags.map(tag => (
                <span key={tag} className={cn(
                  "text-[10px] uppercase font-mono px-2 py-0.5 rounded border font-bold",
                  tag === 'CRITICAL' && "bg-[#ff3b5c]/20 text-[#ff3b5c] border-[#ff3b5c]/50",
                  tag === 'HIGH' && "bg-[#ffaa00]/20 text-[#ffaa00] border-[#ffaa00]/50",
                  tag === 'IOC' && "bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/50",
                )}>
                  {tag}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className={cn(
          "text-[0.9rem] leading-relaxed",
          isAssistant ? "text-[#e8ecf4]" : "text-[#8b95a8]"
        )}>
          {isAssistant ? (
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                code({ node, className, children, ...props }) {
                  const match = /language-(\w+)/.exec(className || '');
                  const isInline = !match && !className?.includes('language-');
                  const contentString = String(children).replace(/\n$/, '');
                  
                  return !isInline ? (
                    <CodeBlock language={match?.[1]} content={contentString} />
                  ) : (
                    <code className="bg-[#1a2236] text-[#00f0ff] px-1.5 py-0.5 rounded text-sm font-mono" {...props}>
                      {children}
                    </code>
                  );
                },
                ul: ({children}) => <ul className="list-disc pl-5 my-2 space-y-1">{children}</ul>,
                ol: ({children}) => <ol className="list-decimal pl-5 my-2 space-y-1">{children}</ol>,
                li: ({children}) => <li>{children}</li>,
                p: ({children}) => <p className="mb-2 last:mb-0">{children}</p>,
                strong: ({children}) => <strong className="font-bold text-white">{children}</strong>,
                h1: ({children}) => <h1 className="text-xl font-bold text-white mt-4 mb-2">{children}</h1>,
                h2: ({children}) => <h2 className="text-lg font-bold text-[#00f0ff] mt-4 mb-2 uppercase tracking-wide">{children}</h2>,
                h3: ({children}) => <h3 className="text-md font-bold text-white mt-3 mb-2">{children}</h3>,
              }}
            >
              {content}
            </ReactMarkdown>
          ) : (
            <p>{content}</p>
          )}
        </div>
      </div>
    </motion.div>
  );
}

function CodeBlock({ language, content }: { language?: string, content: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group my-3 rounded-md overflow-hidden border border-[#2a303f] bg-[#0c1019]">
      <div className="flex items-center justify-between px-4 py-1.5 bg-[#121828] border-b border-[#2a303f]">
        <span className="text-xs font-mono text-[#8b95a8] uppercase">
          {language || 'IOC / SCRIPT'}
        </span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-xs text-[#8b95a8] hover:text-[#00f0ff] transition-colors"
        >
          {copied ? <Check size={14} className="text-[#00ff88]" /> : <Copy size={14} />}
          {copied ? <span className="text-[#00ff88]">Copied</span> : <span>Copy</span>}
        </button>
      </div>
      <div className="relative p-4 overflow-x-auto">
        {/* Glow effect on hover */}
        <div className="absolute inset-0 opacity-0 group-hover:opacity-10 pointer-events-none transition-opacity bg-gradient-to-r from-[#00f0ff] to-transparent mix-blend-overlay"></div>
        <pre className="text-sm font-mono text-[#e8ecf4] whitespace-pre-wrap break-all">
          <code>{content}</code>
        </pre>
      </div>
    </div>
  );
}
