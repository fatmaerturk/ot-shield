import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { User } from '../types/user';
import { Icon } from './theme';
import { useAppMode, AppMode } from '../contexts/AppModeContext';

interface NavigationProps {
  user?: User;
}

/**
 * Visibility modes for a nav entry. Default is both modes; entries
 * flagged {@code 'research'} only show in Research mode (Research,
 * Admin) and entries flagged {@code 'soc'} only in SOC mode (Operate,
 * Detect, Respond, Deception, Govern). Executive is the landing
 * pod for SOC mode and should also hide in Research mode so the
 * focus stays tight.
 */
type NavVisibility = 'research' | 'soc' | 'both';

interface NavChild {
  label: string;
  path: string;
  description?: string;
  icon?: React.ReactNode;
  modes?: NavVisibility;
}

interface NavItem {
  label: string;
  path?: string;
  match?: (p: string) => boolean;
  children?: NavChild[];
  icon?: React.ReactNode;
  emphasis?: boolean;
  modes?: NavVisibility;
}

/**
 * Predicate used when filtering nav items against the current app
 * mode. An item is visible when its {@code modes} flag matches, or
 * when it has no flag at all (= {@code 'both'}).
 */
function itemVisibleIn(mode: AppMode, vis?: NavVisibility): boolean {
  const v = vis ?? 'both';
  if (v === 'both') return true;
  return (v === 'research' && mode === 'RESEARCH')
      || (v === 'soc'      && mode === 'SOC');
}

const NAV: NavItem[] = [
  {
    label: 'Executive',
    path: '/executive',
    icon: <Icon.Shield className="w-4 h-4" />,
    emphasis: true,
    modes: 'soc',
  },
  {
    label: 'Operate',
    modes: 'soc',
    icon: <Icon.Activity className="w-4 h-4" />,
    match: (p) => p === '/dashboard' || p === '/assets' || p === '/network-topology',
    children: [
      {
        label: 'Network Dashboard',
        path: '/dashboard',
        description: 'PCAP capture & live traffic analysis',
        icon: <Icon.Activity className="w-4 h-4" />,
      },
      {
        label: 'Assets',
        path: '/assets',
        description: 'OT/IT inventory and risk posture',
        icon: <Icon.Server className="w-4 h-4" />,
      },
      {
        label: 'Network Topology',
        path: '/network-topology',
        description: 'Purdue Model live view',
        icon: <Icon.Network className="w-4 h-4" />,
      },
    ],
  },
  {
    label: 'Detect',
    modes: 'soc',
    icon: <Icon.Search className="w-4 h-4" />,
    match: (p) =>
      p === '/anomalies' || p === '/mitre-matrix' || p.startsWith('/threat-intelligence') || p.startsWith('/threat-intel'),
    children: [
      {
        label: 'Anomaly Detection',
        path: '/anomalies',
        description: 'AI-powered anomaly stream',
        icon: <Icon.Brain className="w-4 h-4" />,
      },
      {
        label: 'MITRE ATT&CK for ICS',
        path: '/mitre-matrix',
        description: 'Adversary tactics & techniques',
        icon: <Icon.Target className="w-4 h-4" />,
      },
      {
        label: 'Threat Intelligence',
        path: '/threat-intelligence',
        description: 'Curated IOCs, CVEs and advisories',
        icon: <Icon.Bolt className="w-4 h-4" />,
      },
      {
        label: 'Attacker TTPs',
        path: '/threat-intel/attackers',
        description: 'TTP matrix, fingerprints & campaigns from decoys',
        icon: <Icon.Target className="w-4 h-4" />,
      },
    ],
  },
  {
    label: 'Respond',
    modes: 'soc',
    icon: <Icon.Alert className="w-4 h-4" />,
    match: (p) => p === '/alerts' || p === '/cases' || p.startsWith('/cases/'),
    children: [
      {
        label: 'Security Alerts',
        path: '/alerts',
        description: 'Live alert stream from sensors, triage & resolve',
        icon: <Icon.Alert className="w-4 h-4" />,
      },
      {
        label: 'Cases',
        path: '/cases',
        description: 'Investigation files - timeline, IOCs, MTTR',
        icon: <Icon.Layers className="w-4 h-4" />,
      },
    ],
  },
  {
    label: 'Deception',
    modes: 'soc',
    icon: <Icon.Eye className="w-4 h-4" />,
    match: (p) => p === '/attack-intelligence' || p === '/otpot' || p === '/decoy' || p.startsWith('/integrations/ics-decoy') || p.startsWith('/integrations/conpot'),
    children: [
      {
        label: 'Decoy Layer',
        path: '/decoy',
        description: 'Live attacker engagement flow & deep payload inspector',
        icon: <Icon.Target className="w-4 h-4" />,
      },
      {
        label: 'Attack Intelligence',
        path: '/attack-intelligence',
        description: 'Fleet-wide honeypot analytics · geo · credentials · OWASP',
        icon: <Icon.Eye className="w-4 h-4" />,
      },
      {
        label: 'ICS Decoy',
        path: '/integrations/ics-decoy',
        description: 'Live decoy telemetry · threat posture · Modbus function codes',
        icon: <Icon.Layers className="w-4 h-4" />,
      },
    ],
  },
  {
    label: 'Research',
    icon: <Icon.Brain className="w-4 h-4" />,
    match: (p) => p.startsWith('/research'),
    children: [
      {
        label: 'Workspace',
        path: '/research/workspace',
        description: 'Active bundle settings, tags, watch folder',
        icon: <Icon.Layers className="w-4 h-4" />,
      },
      {
        label: 'Knowledge Library',
        path: '/research/library',
        description: 'Vendor manuals & datasheets cited by the copilot',
        icon: <Icon.Server className="w-4 h-4" />,
      },
      {
        label: 'Summary',
        path: '/research/summary',
        description: 'LLM technical summary of this bundle',
        icon: <Icon.Bolt className="w-4 h-4" />,
      },
      {
        label: 'Inventory',
        path: '/research/inventory',
        description: 'Components and protocols identified from the corpus',
        icon: <Icon.Network className="w-4 h-4" />,
      },
      {
        label: 'Ports & services',
        path: '/research/ports',
        description: 'Physical/logical ports and running services',
        icon: <Icon.Activity className="w-4 h-4" />,
      },
      {
        label: 'Threads',
        path: '/research/threads',
        description: 'Persistent copilot conversations with cited sources',
        icon: <Icon.Brain className="w-4 h-4" />,
      },
      {
        label: 'Findings',
        path: '/research/findings',
        description: 'Curated knowledge ledger of approved answers',
        icon: <Icon.CheckCircle className="w-4 h-4" />,
      },
      {
        label: 'Vulns',
        path: '/research/vulns',
        description: 'Vulnerability observations with confidence + lifecycle',
        icon: <Icon.Shield className="w-4 h-4" />,
      },
    ],
  },
  {
    label: 'Govern',
    modes: 'soc',
    icon: <Icon.CheckCircle className="w-4 h-4" />,
    match: (p) => p.startsWith('/compliance') || p === '/hazop',
    children: [
      {
        label: 'NIS2 Compliance',
        path: '/compliance/nis2',
        description: 'Network and Information Security Directive 2',
        icon: <Icon.CheckCircle className="w-4 h-4" />,
      },
      {
        label: 'HAZOP Analysis',
        path: '/hazop',
        description: 'Hazard & operability safety review',
        icon: <Icon.Lock className="w-4 h-4" />,
      },
    ],
  },
  {
    label: 'Admin',
    icon: <Icon.Users className="w-4 h-4" />,
    path: '/user-management',
  },
];

const Navigation: React.FC<NavigationProps> = ({ user }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { mode, setMode } = useAppMode();
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const closeTimer = useRef<number | null>(null);

  // Filter the nav tree against the current mode. Children inherit
  // the group default when they don't set their own `modes` flag, so
  // the "Research" group flows through unchanged in both modes while
  // SOC groups silently collapse in research mode.
  const visibleNav = NAV
    .filter((item) => itemVisibleIn(mode, item.modes))
    .map((item) => item.children
      ? { ...item, children: item.children.filter((c) => itemVisibleIn(mode, c.modes ?? item.modes)) }
      : item);

  // Close any open dropdown on route change
  useEffect(() => {
    setOpenMenu(null);
    setMobileOpen(false);
  }, [location.pathname]);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('[data-nav-root]')) {
        setOpenMenu(null);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
  };

  const isActive = (item: NavItem) =>
    !!((item.path && location.pathname === item.path) ||
      (item.match && item.match(location.pathname)));

  const openDropdown = (label: string) => {
    if (closeTimer.current) {
      window.clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
    setOpenMenu(label);
  };

  const scheduleClose = () => {
    if (closeTimer.current) window.clearTimeout(closeTimer.current);
    closeTimer.current = window.setTimeout(() => setOpenMenu(null), 120);
  };

  return (
    <header
      className="fixed top-0 left-0 right-0 z-[9999] border-b border-white/10"
      style={{
        background:
          'linear-gradient(90deg, rgba(30,27,75,0.95) 0%, rgba(76,29,149,0.95) 50%, rgba(124,58,237,0.95) 100%)',
        backdropFilter: 'blur(12px)',
      }}
      data-nav-root
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16 items-center">
          <div className="flex items-center gap-1">
            {/* Logo */}
            <button
              onClick={() => navigate(mode === 'RESEARCH' ? '/research/threads' : '/executive')}
              className="flex items-center gap-2 pr-4 mr-2 border-r border-white/10 group"
              title={mode === 'RESEARCH' ? 'Go to Research Studio' : 'Go to Executive Briefing'}
            >
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-pink-400 to-violet-400 flex items-center justify-center shadow-lg shadow-violet-500/30 group-hover:shadow-pink-500/40 transition">
                <Icon.Shield className="w-5 h-5 text-white" />
              </div>
              <span className="text-white font-bold text-sm tracking-tight hidden sm:block">
                OTSHIELD
              </span>
            </button>

            {/* Desktop nav */}
            <nav className="hidden lg:flex items-center gap-1">
              {visibleNav.map((item) => {
                const active = isActive(item);
                if (item.children) {
                  const isOpen = openMenu === item.label;
                  return (
                    <div
                      key={item.label}
                      className="relative"
                      onMouseEnter={() => openDropdown(item.label)}
                      onMouseLeave={scheduleClose}
                    >
                      <button
                        onClick={() => setOpenMenu(isOpen ? null : item.label)}
                        aria-haspopup="true"
                        aria-expanded={isOpen}
                        className={`px-3 py-2 rounded-lg text-sm font-medium inline-flex items-center gap-1.5 transition ${
                          active
                            ? 'bg-white/15 text-white shadow-inner ring-1 ring-white/10'
                            : 'text-violet-100 hover:bg-white/10 hover:text-white'
                        }`}
                      >
                        {item.icon && <span className="opacity-80">{item.icon}</span>}
                        <span>{item.label}</span>
                        <svg
                          className={`w-3.5 h-3.5 opacity-70 transition-transform duration-200 ${
                            isOpen ? 'rotate-180' : ''
                          }`}
                          viewBox="0 0 20 20"
                          fill="currentColor"
                        >
                          <path
                            fillRule="evenodd"
                            d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z"
                            clipRule="evenodd"
                          />
                        </svg>
                      </button>

                      <div
                        className={`absolute left-0 mt-1 w-72 bg-white rounded-2xl shadow-2xl ring-1 ring-violet-200/50 z-[9999] overflow-hidden origin-top-left transition-all duration-150 ${
                          isOpen
                            ? 'opacity-100 scale-100 translate-y-0 pointer-events-auto'
                            : 'opacity-0 scale-95 -translate-y-1 pointer-events-none'
                        }`}
                        onMouseEnter={() => openDropdown(item.label)}
                        onMouseLeave={scheduleClose}
                      >
                        <div className="px-4 py-2.5 bg-gradient-to-r from-violet-50 to-fuchsia-50 border-b border-violet-100">
                          <div className="text-[10px] font-bold uppercase tracking-wider text-violet-700">
                            {item.label}
                          </div>
                        </div>
                        <div className="py-1.5">
                          {item.children.map((child) => {
                            const childActive = location.pathname === child.path;
                            return (
                              <button
                                key={child.path}
                                onClick={() => {
                                  navigate(child.path);
                                  setOpenMenu(null);
                                }}
                                className={`w-full text-left px-4 py-2.5 flex items-start gap-3 transition ${
                                  childActive
                                    ? 'bg-violet-50'
                                    : 'hover:bg-slate-50'
                                }`}
                              >
                                <div
                                  className={`mt-0.5 w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 ${
                                    childActive
                                      ? 'bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white'
                                      : 'bg-slate-100 text-slate-500'
                                  }`}
                                >
                                  {child.icon}
                                </div>
                                <div className="min-w-0 flex-1">
                                  <div
                                    className={`text-sm font-semibold ${
                                      childActive ? 'text-violet-700' : 'text-slate-900'
                                    }`}
                                  >
                                    {child.label}
                                  </div>
                                  {child.description && (
                                    <div className="text-xs text-slate-500 mt-0.5 leading-snug">
                                      {child.description}
                                    </div>
                                  )}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  );
                }
                return (
                  <button
                    key={item.label}
                    onClick={() => item.path && navigate(item.path)}
                    className={`px-3 py-2 rounded-lg text-sm font-medium inline-flex items-center gap-1.5 transition ${
                      active
                        ? item.emphasis
                          ? 'bg-gradient-to-r from-pink-500/30 to-violet-500/30 text-white ring-1 ring-white/20 shadow-inner'
                          : 'bg-white/15 text-white shadow-inner ring-1 ring-white/10'
                        : item.emphasis
                          ? 'text-white hover:bg-white/15 ring-1 ring-white/15'
                          : 'text-violet-100 hover:bg-white/10 hover:text-white'
                    }`}
                  >
                    {item.icon && <span className="opacity-80">{item.icon}</span>}
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          <div className="flex items-center gap-3">
            {/* Mode toggle pill — two-segment switch between Research
                and SOC. Research segment lives on the left because
                that's the default in this build; the gradient chip
                slides under the active segment. Hidden on narrow
                screens where the user badge already eats the gutter. */}
            <div
              className="hidden sm:inline-flex items-center rounded-full bg-white/10 ring-1 ring-white/15 p-0.5"
              role="radiogroup"
              aria-label="Application mode"
            >
              <button
                type="button"
                role="radio"
                aria-checked={mode === 'RESEARCH'}
                onClick={() => {
                  setMode('RESEARCH');
                  if (location.pathname === '/' || location.pathname === '/executive') {
                    navigate('/research/threads');
                  }
                }}
                className={`px-3 py-1 rounded-full text-[11px] font-semibold transition ${
                  mode === 'RESEARCH'
                    ? 'bg-gradient-to-r from-fuchsia-500 to-violet-500 text-white shadow-lg shadow-violet-500/30'
                    : 'text-violet-100 hover:text-white'
                }`}
                title="Tear-down assistant focus: library, threads, findings, vulns"
              >
                Research
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={mode === 'SOC'}
                onClick={() => {
                  setMode('SOC');
                  if (location.pathname.startsWith('/research')) {
                    navigate('/executive');
                  }
                }}
                className={`px-3 py-1 rounded-full text-[11px] font-semibold transition ${
                  mode === 'SOC'
                    ? 'bg-gradient-to-r from-sky-500 to-violet-500 text-white shadow-lg shadow-violet-500/30'
                    : 'text-violet-100 hover:text-white'
                }`}
                title="Full OTShield SOC: alerts, cases, decoys, compliance"
              >
                SOC
              </button>
            </div>

            {user && (
              <>
                <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/10 ring-1 ring-white/15">
                  <div className="w-6 h-6 rounded-full bg-gradient-to-br from-pink-400 to-violet-400 flex items-center justify-center text-[10px] font-bold text-white">
                    {user.username?.slice(0, 1).toUpperCase()}
                  </div>
                  <span className="text-xs font-medium text-violet-50">{user.username}</span>
                </div>
                <button
                  onClick={handleLogout}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-white/10 ring-1 ring-white/20 hover:bg-white/20 transition"
                >
                  Logout
                </button>
              </>
            )}

            {/* Mobile menu toggle */}
            <button
              onClick={() => setMobileOpen((v) => !v)}
              className="lg:hidden p-2 rounded-lg text-white bg-white/10 ring-1 ring-white/15 hover:bg-white/20 transition"
              aria-label="Toggle menu"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {mobileOpen ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                )}
              </svg>
            </button>
          </div>
        </div>

        {/* Mobile nav drawer */}
        {mobileOpen && (
          <div className="lg:hidden pb-4 pt-2 space-y-1 max-h-[calc(100vh-4rem)] overflow-y-auto">
            {visibleNav.map((item) => {
              const active = isActive(item);
              if (item.children) {
                return (
                  <div key={item.label} className="rounded-xl bg-white/5 ring-1 ring-white/10 overflow-hidden">
                    <div className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-violet-200 bg-white/5">
                      {item.label}
                    </div>
                    <div className="py-1">
                      {item.children.map((child) => {
                        const childActive = location.pathname === child.path;
                        return (
                          <button
                            key={child.path}
                            onClick={() => navigate(child.path)}
                            className={`w-full text-left px-3 py-2.5 text-sm flex items-center gap-2.5 transition ${
                              childActive
                                ? 'bg-white/15 text-white font-semibold'
                                : 'text-violet-100 hover:bg-white/10'
                            }`}
                          >
                            <span className="opacity-70">{child.icon}</span>
                            {child.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              }
              return (
                <button
                  key={item.label}
                  onClick={() => item.path && navigate(item.path)}
                  className={`w-full text-left px-3 py-2.5 rounded-xl text-sm font-medium flex items-center gap-2.5 transition ${
                    active
                      ? 'bg-white/15 text-white'
                      : 'text-violet-100 hover:bg-white/10'
                  }`}
                >
                  {item.icon && <span className="opacity-80">{item.icon}</span>}
                  {item.label}
                </button>
              );
            })}
          </div>
        )}
      </div>
    </header>
  );
};

export default Navigation;
