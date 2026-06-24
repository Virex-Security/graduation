import React, { useState, useRef, useEffect, memo, useCallback } from 'react';
import {
  XMarkIcon,
  PaperAirplaneIcon,
  CpuChipIcon,
} from '@heroicons/react/24/outline';
import { useAuth } from '../utils/useAuth';

// ---------------------------------------------------------------------------
// Typing indicator — unchanged from original
// ---------------------------------------------------------------------------
function TypingIndicator() {
  return (
    <div
      className="flex justify-start"
      role="status"
      aria-live="polite"
      aria-label="Dobby is typing"
    >
      <div className="flex max-w-[85%] items-center gap-3">
        <div
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-border-dim/50 bg-bg-card/80 text-brand-primary backdrop-blur-sm"
          aria-hidden
        >
          <CpuChipIcon className="h-4 w-4" />
        </div>
        <div className="rounded-2xl rounded-bl-md border border-white/[0.07] bg-white/[0.06] px-4 py-3 shadow-inner backdrop-blur-md">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-brand-primary/80 motion-reduce:animate-none animate-chat-dot" />
            <span className="h-2 w-2 rounded-full bg-brand-primary/80 motion-reduce:animate-none animate-chat-dot-delay-1" />
            <span className="h-2 w-2 rounded-full bg-brand-primary/80 motion-reduce:animate-none animate-chat-dot-delay-2" />
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// DobbyBrainIcon — a custom SVG brain/circuit logo for the FAB
// ---------------------------------------------------------------------------
function DobbyBrainIcon({ className = 'h-7 w-7' }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      {/* Brain outline paths */}
      <path d="M9.5 2a4.5 4.5 0 0 1 4.5 4.5V8" />
      <path d="M14 8a3 3 0 0 1 3 3v1" />
      <path d="M17 12a3 3 0 0 1 3 3v1" />
      <path d="M20 16a2.5 2.5 0 0 1-2.5 2.5H12" />
      <path d="M9.5 2a4 4 0 0 0-4 4v.5" />
      <path d="M5.5 6.5A3 3 0 0 0 4 9.5v1" />
      <path d="M4 10.5a3 3 0 0 0 0 5" />
      <path d="M4 15.5A2.5 2.5 0 0 0 6.5 18H12" />
      {/* Circuit nodes */}
      <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
      <circle cx="12" cy="18" r="1" fill="currentColor" stroke="none" />
      {/* Connecting spine */}
      <line x1="12" y1="8" x2="12" y2="22" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Main Chatbot component
// ---------------------------------------------------------------------------
export default memo(function Chatbot() {
  const { user } = useAuth();

  // ── state ──────────────────────────────────────────────────────────────
  const [isOpen, setIsOpen] = useState(false);
  const [showGreeting, setShowGreeting] = useState(true);
  const [notifCount] = useState(1); // static badge count — lift to prop if needed
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([
    {
      id: 1,
      text: `Hello ${user?.username || 'Guest'}! I'm Dobby, your AI Security Assistant. How can I help you today?`,
      sender: 'bot',
      timestamp: new Date(),
    },
  ]);
  const [isTyping, setIsTyping] = useState(false);

  const scrollRef = useRef(null);
  const panelRef = useRef(null);

  // ── Auto-scroll to bottom on new messages ───────────────────────────────
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  // ── Escape key closes panel ─────────────────────────────────────────────
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e) => {
      if (e.key === 'Escape') setIsOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen]);

  // ── Auto-dismiss greeting bubble after 6 seconds ────────────────────────
  useEffect(() => {
    if (!showGreeting) return;
    const timer = setTimeout(() => setShowGreeting(false), 6000);
    return () => clearTimeout(timer);
  }, [showGreeting]);

  // ── Toggle chat open/close ──────────────────────────────────────────────
  const handleFabClick = useCallback(() => {
    setShowGreeting(false); // dismiss greeting on any interaction
    setIsOpen((prev) => !prev);
  }, []);

  // ── Mock AI response ────────────────────────────────────────────────────
  const getMockResponse = useCallback((txt) => {
    const t = txt.toLowerCase();
    if (t.includes('attack') || t.includes('incident')) {
      return "I've detected 3 recent incidents. You can check the 'Incidents' page for detailed analysis and source IPs.";
    }
    if (t.includes('status') || t.includes('health')) {
      return 'The VIREX engine is currently stable. API latency is 42ms and ML confidence is at 94%.';
    }
    if (t.includes('block') || t.includes('ip')) {
      return 'You can block IPs directly from the Incident Details page or use the Blacklist Management tool.';
    }
    return "I'm not sure about that specifically, but I can help you navigate the security dashboard or explain ML detection scores.";
  }, []);

  // ── Send message ────────────────────────────────────────────────────────
  const handleSend = async (e) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMsg = { id: Date.now(), text: input, sender: 'user', timestamp: new Date() };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    setTimeout(() => {
      const response = getMockResponse(input);
      setMessages((prev) => [
        ...prev,
        { id: Date.now() + 1, text: response, sender: 'bot', timestamp: new Date() },
      ]);
      setIsTyping(false);
    }, 1000);
  };

  // ── Render ──────────────────────────────────────────────────────────────
  return (
    <>
      {/* ================================================================
          CHAT PANEL — exact original styling, zero changes
          ================================================================ */}
      <div
        ref={panelRef}
        id="dobby-chat-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="dobby-chat-title"
        aria-hidden={!isOpen}
        className={`pointer-events-auto fixed bottom-[5.5rem] right-5 flex max-h-[min(32rem,85vh)] w-[min(100vw-2rem,22.5rem)] origin-bottom-right flex-col overflow-hidden rounded-ds-xl border border-white/[0.1] bg-bg-secondary/70 shadow-chat-panel backdrop-blur-xl transition-all duration-300 ease-[cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none sm:bottom-24 sm:right-6 sm:w-96 z-[60] ${
          isOpen
            ? 'translate-y-0 scale-100 opacity-100 pointer-events-auto'
            : 'pointer-events-none translate-y-3 scale-[0.96] opacity-0'
        }`}
      >
        {/* Glass sheen overlay */}
        <div
          className="pointer-events-none absolute inset-0 bg-gradient-to-b from-white/[0.06] to-transparent"
          aria-hidden
        />

        {/* ── Header ── */}
        <header className="relative z-10 flex items-center justify-between border-b border-white/[0.08] bg-brand-primary/10 px-4 py-3 backdrop-blur-md">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-ds-lg border border-brand-primary/30 bg-brand-primary/20 text-brand-primary shadow-inner">
              <CpuChipIcon className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <div
                id="dobby-chat-title"
                className="truncate text-ds-body-sm font-bold text-text-primary"
              >
                Dobby AI
              </div>
              <div className="mt-0.5 flex items-center gap-ds-1 text-ds-micro font-medium text-success">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-success motion-reduce:animate-none" />
                Online
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setIsOpen(false)}
            className="rounded-ds-md p-2 text-text-muted transition-colors hover:bg-white/5 hover:text-text-primary"
            aria-label="Close chat"
          >
            <XMarkIcon className="h-5 w-5" />
          </button>
        </header>

        {/* ── Messages ── */}
        <div
          ref={scrollRef}
          className="relative z-10 flex flex-1 flex-col gap-3 overflow-y-auto overscroll-contain bg-bg-main/20 px-4 py-4 custom-scrollbar"
        >
          {messages.map((m) => (
            <div
              key={m.id}
              className={`flex ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {m.sender === 'bot' && (
                <div
                  className="mr-2 mt-1 hidden h-7 w-7 shrink-0 items-center justify-center rounded-full border border-border-dim/50 bg-bg-card/80 text-brand-primary backdrop-blur-sm sm:flex"
                  aria-hidden
                >
                  <CpuChipIcon className="h-3.5 w-3.5" />
                </div>
              )}
              <div
                className={`max-w-[min(85%,18rem)] px-3.5 py-2.5 text-ds-caption leading-relaxed sm:text-ds-body-sm ${
                  m.sender === 'user'
                    ? 'rounded-2xl rounded-br-md bg-brand-gradient text-white shadow-md shadow-brand-primary/20'
                    : 'rounded-2xl rounded-bl-md border border-white/[0.08] bg-white/[0.07] text-text-secondary shadow-sm backdrop-blur-md'
                }`}
              >
                {m.text}
              </div>
            </div>
          ))}
          {isTyping ? <TypingIndicator /> : null}
        </div>

        {/* ── Input form ── */}
        <form
          onSubmit={handleSend}
          className="relative z-10 border-t border-white/[0.08] bg-bg-secondary/50 p-3 backdrop-blur-md"
        >
          <div className="flex items-end gap-2">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSend(e);
                }
              }}
              placeholder="Ask Dobby about threats…"
              rows={1}
              className="max-h-28 min-h-[2.75rem] flex-1 resize-none rounded-ds-lg border border-border-dim/80 bg-bg-main/60 px-3 py-2.5 text-ds-caption text-text-primary placeholder:text-text-muted shadow-inner backdrop-blur-sm transition-colors focus:border-brand-primary focus:outline-none focus:ring-2 focus:ring-brand-primary/25 sm:text-ds-body-sm"
              aria-label="Message to Dobby"
            />
            <button
              type="submit"
              disabled={!input.trim()}
              className="flex h-11 w-11 shrink-0 items-center justify-center rounded-ds-lg bg-brand-primary/90 text-white shadow-md transition-all hover:bg-brand-primary disabled:cursor-not-allowed disabled:opacity-35 motion-safe:active:scale-95"
              aria-label="Send message"
            >
              <PaperAirplaneIcon className="h-5 w-5 -rotate-12" />
            </button>
          </div>
        </form>
      </div>

      {/* ================================================================
          FAB ROW — greeting bubble + circular trigger button
          Laid out as a fixed row: [bubble] [circular button]
          ================================================================ */}
      <div
        className="fixed bottom-5 right-5 z-[61] flex items-center gap-3 sm:bottom-6 sm:right-6"
        aria-label="Dobby chatbot launcher"
      >
        {/* ── Welcome speech bubble ─────────────────────────────────── */}
        <div
          aria-hidden={!showGreeting}
          className={`relative flex items-center gap-2 transition-all duration-500 ease-out motion-reduce:transition-none ${
            showGreeting && !isOpen
              ? 'translate-x-0 opacity-100 pointer-events-auto'
              : 'translate-x-4 opacity-0 pointer-events-none'
          }`}
        >
          {/* Pill bubble */}
          <div
            className="flex items-center gap-2 rounded-full border border-white/[0.12] bg-bg-secondary/90 px-4 py-2.5 shadow-chat-panel backdrop-blur-xl"
            style={{ boxShadow: '0 8px 24px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.06)' }}
          >
            {/* Pulsing dot */}
            <span
              className="h-2 w-2 shrink-0 animate-pulse rounded-full bg-brand-primary motion-reduce:animate-none"
              aria-hidden
            />
            <span className="whitespace-nowrap text-ds-body-sm font-medium text-text-primary">
              Hi! How may I help you?
            </span>
          </div>

          {/* Tail pointer pointing right toward the FAB */}
          <div
            className="absolute -right-[7px] top-1/2 h-3 w-3 -translate-y-1/2 rotate-45 rounded-sm border-r border-t border-white/[0.12] bg-bg-secondary/90 backdrop-blur-xl"
            aria-hidden
          />

          {/* Dismiss × button */}
          <button
            type="button"
            onClick={() => setShowGreeting(false)}
            aria-label="Dismiss greeting"
            className="absolute -right-2 -top-2 flex h-5 w-5 items-center justify-center rounded-full bg-bg-card/90 text-text-muted shadow-md ring-1 ring-white/10 transition-colors hover:text-text-primary"
          >
            <XMarkIcon className="h-3 w-3" />
          </button>
        </div>

        {/* ── Circular FAB ──────────────────────────────────────────── */}
        <div className="relative shrink-0">
          {/* Notification badge */}
          {notifCount > 0 && !isOpen && (
            <span
              aria-label={`${notifCount} new notification`}
              className="absolute -right-1 -top-1 z-10 flex h-5 w-5 items-center justify-center rounded-full bg-danger text-[10px] font-bold leading-none text-white shadow-md ring-2 ring-bg-main"
            >
              {notifCount}
            </span>
          )}

          {/* Button */}
          <button
            type="button"
            id="dobby-fab"
            onClick={handleFabClick}
            aria-label={isOpen ? 'Close Dobby assistant' : 'Open Dobby assistant'}
            aria-expanded={isOpen}
            aria-controls="dobby-chat-panel"
            className="relative flex h-14 w-14 items-center justify-center rounded-full bg-brand-gradient text-white shadow-chat-fab transition-all duration-300 ease-out motion-reduce:transition-none hover:scale-105 hover:shadow-glow-purple focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-primary active:scale-95"
          >
            {/* Rotating icon between open/close states */}
            <span
              className={`absolute inset-0 flex items-center justify-center transition-all duration-300 ${
                isOpen ? 'rotate-90 opacity-100 scale-100' : 'rotate-0 opacity-0 scale-75'
              }`}
              aria-hidden
            >
              <XMarkIcon className="h-6 w-6" />
            </span>
            <span
              className={`absolute inset-0 flex items-center justify-center transition-all duration-300 ${
                isOpen ? 'rotate-90 opacity-0 scale-75' : 'rotate-0 opacity-100 scale-100'
              }`}
              aria-hidden
            >
              <DobbyBrainIcon className="h-7 w-7" />
            </span>
          </button>

          {/* Soft glow ring behind button */}
          <div
            className="pointer-events-none absolute inset-0 rounded-full opacity-40 blur-md"
            style={{ background: 'linear-gradient(135deg, #e046ba 0%, #b347e6 100%)' }}
            aria-hidden
          />
        </div>
      </div>
    </>
  );
});
