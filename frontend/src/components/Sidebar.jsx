import { NavLink } from 'react-router-dom';
import { 
  HomeIcon, 
  ExclamationTriangleIcon, 
  ShieldCheckIcon, 
  CpuChipIcon, 
  NoSymbolIcon, 
  ShieldExclamationIcon, 
  GlobeAltIcon, 
  CurrencyDollarIcon, 
  Cog8ToothIcon,
  UsersIcon,
  LockClosedIcon,
  TrashIcon,
  ArrowRightOnRectangleIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';

export default function Sidebar({ user, onLogout, isOpen, onToggle }) {
  const isAdmin = user?.role === 'admin';

  const navItems = [
    { label: 'Dashboard', path: '/dashboard', icon: HomeIcon },
    { label: 'Incidents', path: '/incidents', icon: ExclamationTriangleIcon },
    { label: 'Attack History', path: '/attack-history', icon: ShieldCheckIcon },
    { label: 'ML Detections', path: '/ml-detections', icon: CpuChipIcon },
    { label: 'Blocked', path: '/blocked', icon: NoSymbolIcon },
    { label: 'Critical', path: '/critical', icon: ShieldExclamationIcon },
    { label: 'All Requests', path: '/requests', icon: GlobeAltIcon },
    { label: 'Upgrade Plan', path: '/pricing', icon: CurrencyDollarIcon },
    { label: 'Settings', path: '/settings', icon: Cog8ToothIcon },
  ];

  const adminItems = [
    { label: 'User Manager', path: '/user-manager', icon: UsersIcon },
    { label: 'Blacklist', path: '/blacklist', icon: LockClosedIcon },
  ];

  return (
    <>
      {/* Backdrop for mobile */}
      {isOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={onToggle}
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-bg-secondary border-r border-border-dim flex flex-col transition-transform duration-300 transform lg:static lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="h-16 flex items-center justify-between px-6 border-b border-border-dim">
          <div className="flex items-center gap-2">
            <span className="brand-text text-xl">VIREX</span>
          </div>
          <button
            onClick={onToggle}
            className="text-text-secondary hover:text-text-primary lg:hidden"
            aria-label="Close sidebar"
          >
            <XMarkIcon className="w-6 h-6" />
          </button>
        </div>

        <div className="p-6 border-b border-border-dim flex flex-col gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-brand-primary/20 flex items-center justify-center text-brand-primary font-bold overflow-hidden">
              {user?.avatar_url ? (
                <img src={user.avatar_url} alt="avatar" className="w-full h-full object-cover" />
              ) : (
                (user?.full_name || user?.username || 'US').substring(0, 2).toUpperCase()
              )}
            </div>
            <div className="min-w-0">
              <div className="font-semibold text-text-primary flex items-center gap-2 truncate">
                {user?.full_name || user?.username || 'User'}
              </div>
              <div className="text-sm text-text-secondary capitalize">{user?.role || 'Guest'}</div>
              <div className="flex items-center gap-2 text-xs text-success mt-1">
                <div className="w-2 h-2 rounded-full bg-success animate-pulse"></div>
                Connected
              </div>
            </div>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto py-4 px-3 flex flex-col gap-1 custom-scrollbar">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              onClick={() => { if (window.innerWidth < 1024) onToggle(); }}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-3 rounded-xl transition-colors duration-200 ${
                  isActive 
                    ? 'bg-brand-primary/10 text-brand-primary font-semibold' 
                    : 'text-text-secondary hover:bg-bg-card hover:text-text-primary'
                }`
              }
            >
              <item.icon className="w-5 h-5" />
              <span>{item.label}</span>
            </NavLink>
          ))}

          {isAdmin && (
            <>
              <div className="text-xs font-semibold text-text-muted mt-4 mb-2 px-4 uppercase tracking-wider">
                Administration
              </div>
              {adminItems.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  onClick={() => { if (window.innerWidth < 1024) onToggle(); }}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-4 py-3 rounded-xl transition-colors duration-200 ${
                      isActive 
                        ? 'bg-brand-primary/10 text-brand-primary font-semibold' 
                        : 'text-text-secondary hover:bg-bg-card hover:text-text-primary'
                    }`
                  }
                >
                  <item.icon className="w-5 h-5" />
                  <span>{item.label}</span>
                </NavLink>
              ))}
              <button 
                className="flex items-center gap-3 px-4 py-3 rounded-xl text-danger hover:bg-danger/10 transition-colors duration-200 mt-2"
              >
                <TrashIcon className="w-5 h-5" />
                <span>Reset Stats</span>
              </button>
            </>
          )}
        </nav>

        <div className="p-4 border-t border-border-dim">
          <button 
            onClick={onLogout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-text-secondary hover:bg-bg-card hover:text-text-primary transition-colors duration-200"
          >
            <ArrowRightOnRectangleIcon className="w-5 h-5" />
            <span>Logout</span>
          </button>
        </div>
      </aside>
    </>
  );
}
