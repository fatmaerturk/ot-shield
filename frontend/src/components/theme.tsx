import React from 'react';
import { motion } from 'framer-motion';

/* =====================================================================
 *  OTSHIELD SHARED DESIGN LANGUAGE
 *  Centralised so every page inherits the same violet / fuchsia / pink
 *  identity, the same gradient hero, and the same card conventions that
 *  were introduced on the Executive Dashboard.
 * ===================================================================== */

/* ---------- Color tokens (Tailwind class fragments) ---------- */
export const theme = {
  gradients: {
    hero: 'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 45%, #7c3aed 100%)',
    heroWarm: 'linear-gradient(120deg, #3b0764 0%, #6d28d9 50%, #be185d 100%)',
    primaryText: 'bg-gradient-to-r from-violet-600 to-pink-600 bg-clip-text text-transparent',
    softFill: 'bg-gradient-to-r from-violet-500 via-fuchsia-500 to-pink-500',
    kpiA: 'from-violet-500 to-fuchsia-500',
    kpiB: 'from-fuchsia-500 to-pink-500',
    kpiC: 'from-pink-500 to-rose-500',
    kpiD: 'from-rose-500 to-orange-500',
  },
  pageBackground:
    'radial-gradient(1200px 600px at 0% -10%, rgba(168,85,247,0.10), transparent 60%),' +
    'radial-gradient(1000px 500px at 100% 0%, rgba(236,72,153,0.08), transparent 60%),' +
    'linear-gradient(180deg, #fafbff 0%, #f5f3ff 100%)',
};

/* ---------- Shared motion variants ---------- */
export const pageContainer = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};
export const pageItem = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.35 } },
};

/* ---------- Inline SVG icon set (no external icon libraries) ---------- */
export const Icon = {
  Shield: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2l8 3v7c0 4.97-3.58 9.16-8 10-4.42-.84-8-5.03-8-10V5l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
  Eye: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  ),
  Brain: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 3a3 3 0 0 0-3 3v1a3 3 0 0 0-3 3v2a3 3 0 0 0 1.5 2.6A3 3 0 0 0 6 19a3 3 0 0 0 3 3 3 3 0 0 0 3-3V6a3 3 0 0 0-3-3z" />
      <path d="M15 3a3 3 0 0 1 3 3v1a3 3 0 0 1 3 3v2a3 3 0 0 1-1.5 2.6A3 3 0 0 1 18 19a3 3 0 0 1-3 3 3 3 0 0 1-3-3V6a3 3 0 0 1 3-3z" />
    </svg>
  ),
  Target: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="6" />
      <circle cx="12" cy="12" r="2" />
    </svg>
  ),
  Alert: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  Clock: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  ),
  Activity: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  ),
  Network: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="5" r="2" />
      <circle cx="5" cy="19" r="2" />
      <circle cx="19" cy="19" r="2" />
      <path d="M12 7v4M12 11l-7 6M12 11l7 6" />
    </svg>
  ),
  CheckCircle: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  ),
  Bolt: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  ),
  Layers: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 2 7 12 12 22 7 12 2" />
      <polyline points="2 17 12 22 22 17" />
      <polyline points="2 12 12 17 22 12" />
    </svg>
  ),
  Server: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  ),
  Lock: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  ),
  Search: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="7" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  ),
  Users: ({ className = 'w-6 h-6' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  ),
  TrendingUp: ({ className = 'w-4 h-4' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 6 13.5 15.5 8.5 10.5 1 18" />
      <polyline points="17 6 23 6 23 12" />
    </svg>
  ),
  TrendingDown: ({ className = 'w-4 h-4' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 18 13.5 8.5 8.5 13.5 1 6" />
      <polyline points="17 18 23 18 23 12" />
    </svg>
  ),
  Arrow: ({ className = 'w-4 h-4' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="5" y1="12" x2="19" y2="12" />
      <polyline points="12 5 19 12 12 19" />
    </svg>
  ),
  Filter: ({ className = 'w-4 h-4' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
    </svg>
  ),
  Refresh: ({ className = 'w-4 h-4' }: { className?: string }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 4 23 10 17 10" />
      <polyline points="1 20 1 14 7 14" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
  ),
};

/* ---------- Page shell: the gradient background + subtle grid ---------- */
export const PageShell: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className = '' }) => (
  <div
    className={`min-h-screen mt-16 relative overflow-hidden ${className}`}
    style={{ background: theme.pageBackground }}
  >
    <div
      aria-hidden
      className="pointer-events-none absolute inset-0 opacity-[0.05]"
      style={{
        backgroundImage:
          'linear-gradient(rgba(124,58,237,0.6) 1px, transparent 1px), linear-gradient(90deg, rgba(124,58,237,0.6) 1px, transparent 1px)',
        backgroundSize: '48px 48px',
      }}
    />
    <motion.div
      className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8"
      variants={pageContainer}
      initial="hidden"
      animate="visible"
    >
      {children}
    </motion.div>
  </div>
);

/* ---------- Page hero: violet gradient with optional actions ---------- */
export const PageHero: React.FC<{
  eyebrow?: string;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  stats?: Array<{ label: string; value: React.ReactNode; sub?: React.ReactNode }>;
}> = ({ eyebrow, title, subtitle, icon, actions, stats }) => (
  <motion.div variants={pageItem} className="mb-8">
    <div
      className="relative overflow-hidden rounded-2xl p-8 md:p-10 text-white"
      style={{ background: theme.gradients.hero }}
    >
      <div
        className="absolute -top-20 -right-20 w-80 h-80 rounded-full"
        style={{ background: 'radial-gradient(closest-side, rgba(236,72,153,0.35), transparent)' }}
      />
      <div
        className="absolute -bottom-24 -left-10 w-72 h-72 rounded-full"
        style={{ background: 'radial-gradient(closest-side, rgba(168,85,247,0.35), transparent)' }}
      />
      <div className="relative flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div className="max-w-3xl">
          {eyebrow && (
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 backdrop-blur-sm ring-1 ring-white/20 text-xs font-medium tracking-wide">
              {icon && <span className="text-pink-300">{icon}</span>}
              {eyebrow}
            </div>
          )}
          <h1 className="mt-4 text-3xl md:text-4xl font-bold leading-tight">{title}</h1>
          {subtitle && <p className="mt-3 text-sm md:text-base text-violet-100/90 leading-relaxed">{subtitle}</p>}
          {stats && (
            <div className="mt-5 grid grid-cols-2 sm:grid-cols-3 gap-3 max-w-2xl">
              {stats.map((s, i) => (
                <div key={i} className="p-3 rounded-xl bg-white/10 ring-1 ring-white/15 backdrop-blur-sm">
                  <div className="text-[10px] uppercase tracking-wider text-violet-200/80">{s.label}</div>
                  <div className="mt-1 text-2xl font-bold">{s.value}</div>
                  {s.sub && <div className="text-[11px] text-violet-200/80">{s.sub}</div>}
                </div>
              ))}
            </div>
          )}
        </div>
        {actions && <div className="flex-shrink-0">{actions}</div>}
      </div>
    </div>
  </motion.div>
);

/* ---------- KPI Card ---------- */
export const KpiCard: React.FC<{
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  icon?: React.ReactNode;
  color?: 'violet' | 'fuchsia' | 'rose' | 'pink';
  progress?: number;
  delta?: { text: string; good?: boolean };
}> = ({ label, value, hint, icon, color = 'violet', progress, delta }) => {
  const gradient: Record<string, string> = {
    violet: theme.gradients.kpiA,
    fuchsia: theme.gradients.kpiB,
    rose: theme.gradients.kpiC,
    pink: theme.gradients.kpiC,
  };
  return (
    <div className="relative bg-white rounded-2xl p-5 ring-1 ring-slate-200/70 shadow-sm hover:shadow-md transition">
      <div className="flex items-center justify-between mb-3">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
        {icon && (
          <div className={`w-9 h-9 rounded-lg bg-gradient-to-br ${gradient[color]} text-white flex items-center justify-center`}>
            {icon}
          </div>
        )}
      </div>
      <div className="text-3xl font-bold text-slate-900 tracking-tight">{value}</div>
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
      {delta && (
        <span
          className={`mt-2 inline-block text-[11px] font-semibold px-2 py-0.5 rounded-full ${
            delta.good ? 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200' : 'bg-rose-50 text-rose-700 ring-1 ring-rose-200'
          }`}
        >
          {delta.text}
        </span>
      )}
      {typeof progress === 'number' && (
        <div className="mt-4 h-1.5 bg-slate-100 rounded-full overflow-hidden">
          <div
            className={`h-full bg-gradient-to-r ${gradient[color]} rounded-full`}
            style={{ width: `${Math.max(0, Math.min(100, progress))}%` }}
          />
        </div>
      )}
    </div>
  );
};

/* ---------- Panel: white rounded card with optional header ---------- */
export const Panel: React.FC<{
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}> = ({ title, subtitle, icon, actions, children, className = '' }) => (
  <div className={`bg-white rounded-2xl p-6 ring-1 ring-slate-200/70 shadow-sm ${className}`}>
    {(title || icon || actions) && (
      <div className="flex items-center justify-between mb-5">
        <div>
          {title && <h3 className="text-base font-semibold text-slate-900">{title}</h3>}
          {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
        </div>
        <div className="flex items-center gap-2">
          {actions}
          {icon && <span className="text-violet-500">{icon}</span>}
        </div>
      </div>
    )}
    {children}
  </div>
);

/* ---------- Severity badge utility ---------- */
export const severityStyle = (sev: string) => {
  const s = sev.toUpperCase();
  switch (s) {
    case 'CRITICAL':
      return { badge: 'bg-rose-100 text-rose-700 ring-rose-200', dot: 'bg-rose-500', bar: 'bg-rose-500', text: 'text-rose-700' };
    case 'HIGH':
      return { badge: 'bg-orange-100 text-orange-700 ring-orange-200', dot: 'bg-orange-500', bar: 'bg-orange-500', text: 'text-orange-700' };
    case 'MEDIUM':
      return { badge: 'bg-amber-100 text-amber-700 ring-amber-200', dot: 'bg-amber-500', bar: 'bg-amber-500', text: 'text-amber-700' };
    case 'LOW':
      return { badge: 'bg-emerald-100 text-emerald-700 ring-emerald-200', dot: 'bg-emerald-500', bar: 'bg-emerald-500', text: 'text-emerald-700' };
    default:
      return { badge: 'bg-slate-100 text-slate-700 ring-slate-200', dot: 'bg-slate-400', bar: 'bg-slate-400', text: 'text-slate-700' };
  }
};

/* ---------- Gradient pill button ---------- */
export const GradientButton: React.FC<{
  onClick?: () => void;
  children: React.ReactNode;
  className?: string;
  variant?: 'solid' | 'ghost';
}> = ({ onClick, children, className = '', variant = 'solid' }) => (
  <button
    onClick={onClick}
    className={
      variant === 'solid'
        ? `inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white bg-gradient-to-r ${theme.gradients.kpiA} hover:shadow-lg hover:shadow-violet-500/30 transition ${className}`
        : `inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-violet-700 bg-violet-50 hover:bg-violet-100 ring-1 ring-violet-200 transition ${className}`
    }
  >
    {children}
  </button>
);
