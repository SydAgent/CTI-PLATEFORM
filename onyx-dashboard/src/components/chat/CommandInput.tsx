"use client";

import React, { useState, useRef, useEffect } from 'react';
import { Send, Terminal } from 'lucide-react';
import { cn } from '@/lib/utils';

interface CommandInputProps {
  onSend: (message: string) => void;
  isLoading: boolean;
}

export function CommandInput({ onSend, isLoading }: CommandInputProps) {
  const [input, setInput] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, [input]);

  const handleSend = () => {
    if (input.trim() && !isLoading) {
      onSend(input.trim());
      setInput('');
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="relative flex items-center bg-[#121828] border border-[#2a303f] rounded-lg p-2 focus-within:border-[#00f0ff] focus-within:shadow-[0_0_15px_rgba(0,240,255,0.2)] transition-all">
      <div className="pl-2 pr-3 text-[#00f0ff]">
        <Terminal size={18} />
      </div>
      <textarea
        ref={textareaRef}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Enter search query, IOC, or tactical command..."
        className="flex-1 bg-transparent text-[#e8ecf4] placeholder-[#5a6478] focus:outline-none resize-none font-mono text-sm max-h-32 min-h-[24px] py-2"
        rows={1}
        disabled={isLoading}
      />
      <button
        onClick={handleSend}
        disabled={!input.trim() || isLoading}
        className={cn(
          "ml-2 p-2 rounded-md transition-all flex items-center justify-center",
          input.trim() && !isLoading 
            ? "bg-[#00f0ff] text-black hover:bg-[#66f7ff] hover:shadow-[0_0_10px_rgba(0,240,255,0.4)]" 
            : "bg-[#1a2236] text-[#5a6478] cursor-not-allowed"
        )}
      >
        <Send size={16} className={cn(isLoading && "opacity-50")} />
      </button>
    </div>
  );
}
