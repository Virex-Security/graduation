import { NavLink, matchPath, useLocation } from 'react-router-dom';
import {
  FiHome,
  FiCpu,
  FiBarChart2,
  FiSettings,
} from 'react-icons/fi';
import {
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  NoSymbolIcon,
  ShieldExclamationIcon,
  GlobeAltIcon,
  CurrencyDollarIcon,
  UsersIcon,
  LockClosedIcon,
  TrashIcon,
  ArrowRightOnRectangleIcon,
  XMarkIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline';

/**
 * Primary destinations (react-icons) + extended nav (heroicons). Active state uses path + optional `matchPaths`.
 */
function PrimaryNavLink({
  to,
  end = false,
  matchPaths,
  icon: Icon,
  label,
  collapsed,
  onNavigate,
}) {
  const { pathname } = useLocation();
  const matchedByPrefix =
    matchPaths?.some((p) => matchPath({ path: p, end: false }, pathname)) ?? false;

  return (
    <NavLink
      to={to}
      end={end}
      onClick={onNavigate}
      title={collapsed ? label : undefined}
      className={({ isActive }) => {
        const active = isActive || matchedByPrefix;
        return [
          'flex items-center gap-3 rounded-xl transition-colors duration-200',
          collapsed ? 'justify-center px-2 py-3 lg:px-2' : 'px-4 py-3',
          active
            ? 'bg-brand-primary/10 text-brand-primary font-semibold'
            : 'text-text-secondary hover:bg-bg-card hover:text-text-primary',
        ].join(' ');
      }}
    >
      <Icon className="w-5 h-5 shrink-0" aria-hidden />
      <span className={collapsed ? 'sr-only' : 'truncate'}>{label}</span>
    </NavLink>
  );
}

function SecondaryNavLink({ to, icon: Icon, label, collapsed, onNavigate }) {
  return (
    <NavLink
      to={to}
      onClick={onNavigate}
      title={collapsed ? label : undefined}
      className={({ isActive }) =>
        [
          'flex items-center gap-3 rounded-xl transition-colors duration-200',
          collapsed ? 'justify-center px-2 py-3 lg:px-2' : 'px-4 py-3',
          isActive
            ? 'bg-brand-primary/10 text-brand-primary font-semibold'
            : 'text-text-secondary hover:bg-bg-card hover:text-text-primary',
        ].join(' ')
      }
    >
      <Icon className="w-5 h-5 shrink-0" aria-hidden />
      <span className={collapsed ? 'sr-only' : 'truncate'}>{label}</span>
    </NavLink>
  );
}

export default function Sidebar({
  user,
  onLogout,
  isOpen,
  onToggle,
  collapsed,
  onToggleCollapse,
}) {
  const isAdmin = user?.role === 'admin';

  const closeMobileIfNeeded = () => {
    if (typeof window !== 'undefined' && window.innerWidth < 1024) onToggle?.();
  };

  const primaryItems = [
    {
      label: 'Dashboard',
      to: '/dashboard',
      end: true,
      icon: FiHome,
    },
    {
      label: 'Scan',
      to: '/requests',
      end: true,
      icon: FiCpu,
    },
    {
      label: 'Reports',
      to: '/attack-history',
      end: false,
      matchPaths: ['/incidents', '/attack-history', '/ml-detections', '/ml-performance'],
      icon: FiBarChart2,
    },
    {
      label: 'Settings',
      to: '/settings',
      end: true,
      icon: FiSettings,
    },
  ];

  const moreItems = [
    { label: 'Incidents', path: '/incidents', icon: ExclamationTriangleIcon },
    { label: 'Attack History', path: '/attack-history', icon: ShieldCheckIcon },
    { label: 'ML Detections', path: '/ml-detections', icon: CpuChipIcon },
    { label: 'Blocked', path: '/blocked', icon: NoSymbolIcon },
    { label: 'Critical', path: '/critical', icon: ShieldExclamationIcon },
    { label: 'All Requests', path: '/requests', icon: GlobeAltIcon },
    { label: 'Upgrade Plan', path: '/pricing', icon: CurrencyDollarIcon },
  ];

  const adminItems = [
    { label: 'User Manager', path: '/user-manager', icon: UsersIcon },
    { label: 'Blacklist', path: '/blacklist', icon: LockClosedIcon },
  ];

  const asideWidth = collapsed
    ? 'w-64 lg:w-[4.5rem]'
    : 'w-64';

  return (
    <>
      {isOpen ? (
        <button
          type="button"
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          aria-label="Close menu"
          onClick={onToggle}
        />
      ) : null}

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex flex-col border-r border-border-dim bg-bg-secondary transition-[width,transform] duration-300 ease-out lg:static lg:translate-x-0 ${asideWidth} ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Main navigation"
      >
        <div className="flex h-16 flex-shrink-0 items-center border-b border-border-dim px-4 sm:px-6">
          <span
            className={`brand-text max-w-[140px] truncate text-ds-title ${
              collapsed ? 'lg:sr-only' : ''
            }`}
          >
            VIREX
          </span>
          <div
            className={`flex items-center gap-1 ${
              collapsed ? 'ml-auto lg:ml-0 lg:flex-1 lg:justify-center' : 'ml-auto'
            }`}
          >
            <button
              type="button"
              onClick={onToggleCollapse}
              className="btn btn-icon btn-ghost hidden lg:flex"
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              aria-expanded={!collapsed}
            >
              {collapsed ? (
                <ChevronRightIcon className="h-5 w-5 text-text-secondary" />
              ) : (
                <ChevronLeftIcon className="h-5 w-5 text-text-secondary" />
              )}
            </button>
            <button
              type="button"
              onClick={onToggle}
              className="btn btn-icon btn-ghost lg:hidden"
              aria-label="Close sidebar"
            >
              <XMarkIcon className="h-6 w-6 text-text-secondary" />
            </button>
          </div>
        </div>

        <div
          className={`flex flex-col gap-4 border-b border-border-dim p-4 ${
            collapsed ? 'items-center lg:px-2' : 'px-6'
          }`}
        >
          <div className={`flex items-center gap-4 ${collapsed ? 'flex-col' : ''}`}>
            <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center overflow-hidden rounded-xl bg-brand-primary/20 text-sm font-bold text-brand-primary">
              {user?.avatar_url ? (
                <img src={user.avatar_url} alt="" className="h-full w-full object-cover" />
              ) : (
                (user?.full_name || user?.username || 'US').substring(0, 2).toUpperCase()
              )}
            </div>
            {!collapsed && (
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 truncate font-semibold text-text-primary">
                  {user?.full_name || user?.username || 'User'}
                </div>
                <div className="text-sm capitalize text-text-secondary">{user?.role || 'Guest'}</div>
                <div className="mt-1 flex items-center gap-2 text-xs text-success">
                  <span className="h-2 w-2 animate-pulse rounded-full bg-success" aria-hidden />
                  Connected
                </div>
              </div>
            )}
          </div>
        </div>

        <nav className="custom-scrollbar flex flex-1 flex-col gap-1 overflow-y-auto px-3 py-4">
          {!collapsed && (
            <div className="mb-1 px-4 text-ds-micro font-semibold uppercase tracking-ds-wider text-text-muted">
              Main
            </div>
          )}
          {primaryItems.map((item) => (
            <PrimaryNavLink
              key={item.label}
              to={item.to}
              end={item.end}
              matchPaths={item.matchPaths}
              icon={item.icon}
              label={item.label}
              collapsed={collapsed}
              onNavigate={closeMobileIfNeeded}
            />
          ))}

          {!collapsed && (
            <div className="mb-1 mt-4 px-4 text-ds-micro font-semibold uppercase tracking-ds-wider text-text-muted">
              More
            </div>
          )}
          {collapsed && <div className="my-2 hidden border-t border-border-dim lg:block" role="separator" />}
          {moreItems.map((item) => (
            <SecondaryNavLink
              key={item.path}
              to={item.path}
              icon={item.icon}
              label={item.label}
              collapsed={collapsed}
              onNavigate={closeMobileIfNeeded}
            />
          ))}

          {isAdmin && (
            <>
              {!collapsed && (
                <div className="mb-1 mt-4 px-4 text-ds-micro font-semibold uppercase tracking-ds-wider text-text-muted">
                  Administration
                </div>
              )}
              {adminItems.map((item) => (
                <SecondaryNavLink
                  key={item.path}
                  to={item.path}
                  icon={item.icon}
                  label={item.label}
                  collapsed={collapsed}
                  onNavigate={closeMobileIfNeeded}
                />
              ))}
              <button
                type="button"
                className={`mt-2 flex items-center gap-3 rounded-xl text-danger transition-colors duration-200 hover:bg-danger/10 ${
                  collapsed ? 'justify-center px-2 py-3' : 'px-4 py-3'
                }`}
                title={collapsed ? 'Reset stats' : undefined}
              >
                <TrashIcon className="h-5 w-5 shrink-0" aria-hidden />
                <span className={collapsed ? 'sr-only' : ''}>Reset Stats</span>
              </button>
            </>
          )}
        </nav>

        <div className="border-t border-border-dim p-4">
          <button
            type="button"
            onClick={onLogout}
            title={collapsed ? 'Logout' : undefined}
            className={`flex w-full items-center gap-3 rounded-xl text-text-secondary transition-colors duration-200 hover:bg-bg-card hover:text-text-primary ${
              collapsed ? 'justify-center px-2 py-3' : 'px-4 py-3'
            }`}
          >
            <ArrowRightOnRectangleIcon className="h-5 w-5 shrink-0" aria-hidden />
            <span className={collapsed ? 'sr-only' : ''}>Logout</span>
          </button>
        </div>
      </aside>
    </>
  );
}
