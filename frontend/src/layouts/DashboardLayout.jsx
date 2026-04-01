import { useState, Suspense } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { BellIcon, MoonIcon, SunIcon, ArrowLeftIcon, Bars3Icon } from '@heroicons/react/24/outline';
import Sidebar from '../components/Sidebar';
import Chatbot from '../components/Chatbot';
import { useAuth } from '../utils/useAuth';

function Navbar({ onThemeToggle, isDark, onMenuToggle }) {
  const navigate = useNavigate();

  return (
    <header
      role="banner"
      className="h-16 border-b border-border-dim bg-bg-secondary/50 backdrop-blur-md flex items-center justify-between px-6 flex-shrink-0 z-30"
    >
      <div className="flex items-center gap-2">
        <button
          onClick={onMenuToggle}
          className="btn btn-icon btn-ghost lg:hidden mr-2"
          aria-label="Open sidebar"
        >
          <Bars3Icon className="w-6 h-6 text-text-secondary" />
        </button>
        
        <button
          onClick={() => navigate(-1)}
          aria-label="Go back"
          className="btn btn-icon btn-ghost hidden sm:flex"
        >
          <ArrowLeftIcon className="w-5 h-5" />
        </button>
        
        <svg
          width="32" height="32"
          viewBox="0 0 100 100"
          aria-label="Virex logo"
          role="img"
          className="cursor-pointer"
          onClick={() => navigate('/')}
        >
          <defs>
            <linearGradient id="v-nav-left" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#9a277d" />
              <stop offset="100%" stopColor="#792b9d" />
            </linearGradient>
            <linearGradient id="v-nav-right" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#e046ba" />
              <stop offset="100%" stopColor="#b347e6" />
            </linearGradient>
          </defs>
          <path d="M25,25 L50,80" stroke="url(#v-nav-left)" strokeWidth="18" strokeLinecap="round" fill="none" />
          <path d="M50,80 L75,25" stroke="url(#v-nav-right)" strokeWidth="18" strokeLinecap="round" fill="none" />
        </svg>
      </div>

      <div className="flex items-center gap-2">
        <button
          className="btn btn-icon btn-ghost"
          aria-label="Notifications"
        >
          <BellIcon className="w-5 h-5 text-text-secondary" />
        </button>

        <button
          onClick={onThemeToggle}
          className="btn btn-icon btn-ghost"
          aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {isDark
            ? <SunIcon className="w-5 h-5 text-text-secondary" />
            : <MoonIcon className="w-5 h-5 text-text-secondary" />
          }
        </button>
      </div>
    </header>
  );
}

export default function DashboardLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [isDark, setIsDark] = useState(true);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const toggleTheme = () => {
    const newDark = !isDark;
    setIsDark(newDark);
    document.documentElement.setAttribute('data-theme', newDark ? 'dark' : 'light');
    if (newDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className={`flex h-screen overflow-hidden bg-bg-main ${isDark ? 'dark' : ''}`}>
      <Sidebar 
        user={user} 
        onLogout={handleLogout} 
        isOpen={isSidebarOpen} 
        onToggle={() => setIsSidebarOpen(!isSidebarOpen)} 
      />

      <div className="flex flex-col flex-1 overflow-hidden relative">
        <Navbar 
          onThemeToggle={toggleTheme} 
          isDark={isDark} 
          onMenuToggle={() => setIsSidebarOpen(true)}
        />

        <main
          id="main-content"
          role="main"
          tabIndex={-1}
          className="flex-1 overflow-y-auto p-4 sm:p-6 focus:outline-none"
        >
          <Suspense fallback={
            <div className="flex items-center justify-center h-full">
              <div className="w-8 h-8 rounded-full border-2 border-brand-primary border-t-transparent animate-spin" aria-label="Loading page" />
            </div>
          }>
            <Outlet />
          </Suspense>
        </main>
      </div>

      <Chatbot />
    </div>
  );
}
