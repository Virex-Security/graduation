import { useState, Suspense } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { BellIcon, MoonIcon, SunIcon, ArrowLeftIcon, Bars3Icon } from '@heroicons/react/24/outline';
import Sidebar from '../components/Sidebar';
import { useAuth } from '../utils/useAuth';

function Navbar({ onThemeToggle, isDark, onMenuToggle }) {
  const navigate = useNavigate();

  return (
    <header
      role="banner"
      className="z-30 flex h-16 flex-shrink-0 items-center justify-between border-b border-border-dim bg-bg-secondary/50 px-4 backdrop-blur-md sm:px-6"
    >
      <div className="flex min-w-0 items-center gap-2">
        <button
          type="button"
          onClick={onMenuToggle}
          className="btn btn-icon btn-ghost mr-1 lg:hidden"
          aria-label="Open sidebar"
        >
          <Bars3Icon className="h-6 w-6 text-text-secondary" />
        </button>

        <button
          type="button"
          onClick={() => navigate(-1)}
          aria-label="Go back"
          className="btn btn-icon btn-ghost hidden sm:flex"
        >
          <ArrowLeftIcon className="h-5 w-5" />
        </button>

        <svg
          width="32"
          height="32"
          viewBox="0 0 100 100"
          aria-label="Virex logo"
          role="img"
          className="hidden shrink-0 cursor-pointer sm:block"
          onClick={() => navigate('/')}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              navigate('/');
            }
          }}
          tabIndex={0}
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
          <path
            d="M25,25 L50,80"
            stroke="url(#v-nav-left)"
            strokeWidth="18"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d="M50,80 L75,25"
            stroke="url(#v-nav-right)"
            strokeWidth="18"
            strokeLinecap="round"
            fill="none"
          />
        </svg>
      </div>

      <div className="flex items-center gap-2">
        <button type="button" className="btn btn-icon btn-ghost" aria-label="Notifications">
          <BellIcon className="h-5 w-5 text-text-secondary" />
        </button>

        <button
          type="button"
          onClick={onThemeToggle}
          className="btn btn-icon btn-ghost"
          aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {isDark ? (
            <SunIcon className="h-5 w-5 text-text-secondary" />
          ) : (
            <MoonIcon className="h-5 w-5 text-text-secondary" />
          )}
        </button>
      </div>
    </header>
  );
}

/**
 * Authenticated shell: sidebar, top bar, main outlet, chatbot.
 */
export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [isDark, setIsDark] = useState(true);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

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
    <div className={`flex h-screen min-h-0 overflow-hidden bg-bg-main ${isDark ? 'dark' : ''}`}>
      <Sidebar
        user={user}
        onLogout={handleLogout}
        isOpen={isSidebarOpen}
        onToggle={() => setIsSidebarOpen((o) => !o)}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed((c) => !c)}
      />

      <div className="relative flex min-w-0 flex-1 flex-col overflow-hidden">
        <Navbar
          onThemeToggle={toggleTheme}
          isDark={isDark}
          onMenuToggle={() => setIsSidebarOpen(true)}
        />

        <main
          id="main-content"
          role="main"
          tabIndex={-1}
          className="focus:outline-none flex-1 overflow-y-auto p-4 sm:p-6"
        >
          <Suspense
            fallback={
              <div className="flex h-full min-h-[40vh] items-center justify-center">
                <div
                  className="h-8 w-8 animate-spin rounded-full border-2 border-brand-primary border-t-transparent"
                  aria-label="Loading page"
                />
              </div>
            }
          >
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  );
}
