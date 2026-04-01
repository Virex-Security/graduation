import React, { useState, useRef, useEffect, memo } from 'react';
import { 
  ChatBubbleLeftEllipsisIcon, 
  XMarkIcon, 
  PaperAirplaneIcon,
  CpuChipIcon
} from '@heroicons/react/24/outline';
import { useAuth } from '../utils/useAuth';

export default memo(function Chatbot() {
  const { user } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([
    { id: 1, text: `Hello ${user?.username || 'Guest'}! I'm Dobby, your AI Security Assistant. How can I help you today?`, sender: 'bot', timestamp: new Date() }
  ]);
  const [isTyping, setIsTyping] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  const handleSend = async (e) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMsg = { id: Date.now(), text: input, sender: 'user', timestamp: new Date() };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    // Mock AI response
    setTimeout(() => {
      const response = getMockResponse(input);
      setMessages(prev => [...prev, { id: Date.now() + 1, text: response, sender: 'bot', timestamp: new Date() }]);
      setIsTyping(false);
    }, 1000);
  };

  const getMockResponse = (txt) => {
    const t = txt.toLowerCase();
    if (t.includes('attack') || t.includes('incident')) return "I've detected 3 recent incidents. You can check the 'Incidents' page for detailed analysis and source IPs.";
    if (t.includes('status') || t.includes('health')) return "The VIREX engine is currently stable. API latency is 42ms and ML confidence is at 94%.";
    if (t.includes('block') || t.includes('ip')) return "You can block IPs directly from the Incident Details page or use the Blacklist Management tool.";
    return "I'm not sure about that specifically, but I can help you navigate the security dashboard or explain ML detection scores.";
  };

  return (
    <>
      {/* FAB */}
      <button
        onClick={() => setIsOpen(true)}
        className={`fixed bottom-6 right-6 w-14 h-14 rounded-full bg-brand-primary shadow-lg shadow-brand-primary/40 flex items-center justify-center text-white transition-all duration-300 hover:scale-110 z-50 ${isOpen ? 'scale-0 opacity-0' : 'scale-100 opacity-100'}`}
        aria-label="Ask Dobby"
      >
        <ChatBubbleLeftEllipsisIcon className="w-7 h-7" />
      </button>

      {/* Chat Window */}
      <div 
        className={`fixed bottom-6 right-6 w-80 sm:w-96 h-[500px] max-h-[80vh] bg-bg-secondary border border-border-dim rounded-2xl shadow-2xl flex flex-col z-50 transition-all duration-300 transform origin-bottom-right ${isOpen ? 'scale-100 opacity-100 translate-y-0' : 'scale-95 opacity-0 translate-y-4 pointer-events-none'}`}
      >
        {/* Header */}
        <div className="p-4 border-b border-border-dim bg-brand-primary/5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-brand-primary/20 flex items-center justify-center text-brand-primary">
              <CpuChipIcon className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold text-text-primary leading-tight font-serif">Dobby AI</div>
              <div className="text-[10px] text-success font-medium flex items-center gap-1">
                <span className="w-1 h-1 rounded-full bg-success animate-pulse" /> Online
              </div>
            </div>
          </div>
          <button onClick={() => setIsOpen(false)} className="text-text-muted hover:text-text-primary p-1">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        {/* Messages */}
        <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar bg-bg-main/30">
          {messages.map((m) => (
            <div key={m.id} className={`flex ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[85%] p-3 rounded-2xl text-xs leading-relaxed ${
                m.sender === 'user' 
                  ? 'bg-brand-primary text-white rounded-tr-none' 
                  : 'bg-bg-card text-text-secondary border border-border-dim/50 rounded-tl-none'
              }`}>
                {m.text}
              </div>
            </div>
          ))}
          {isTyping && (
            <div className="flex justify-start">
              <div className="bg-bg-card p-3 rounded-2xl rounded-tl-none border border-border-dim/50 flex gap-1">
                <div className="w-1 h-1 rounded-full bg-text-muted animate-bounce" />
                <div className="w-1 h-1 rounded-full bg-text-muted animate-bounce [animation-delay:0.2s]" />
                <div className="w-1 h-1 rounded-full bg-text-muted animate-bounce [animation-delay:0.4s]" />
              </div>
            </div>
          )}
        </div>

        {/* Input */}
        <form onSubmit={handleSend} className="p-3 border-t border-border-dim bg-bg-secondary/50">
          <div className="relative flex items-center">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(e); } }}
              placeholder="Ask Dobby about threats..."
              rows={1}
              className="w-full bg-bg-main border border-border-dim rounded-xl px-4 py-2.5 text-xs text-text-primary focus:outline-none focus:border-brand-primary resize-none pr-10"
            />
            <button 
              type="submit" 
              className={`absolute right-2 text-brand-primary hover:text-brand-secondary transition-colors ${!input.trim() ? 'opacity-30' : 'opacity-100'}`}
              disabled={!input.trim()}
            >
              <PaperAirplaneIcon className="w-5 h-5" />
            </button>
          </div>
        </form>
      </div>
    </>
  );
});
