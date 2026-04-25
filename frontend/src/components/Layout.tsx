import React from 'react';
import Navigation from './Navigation';
import { User } from '../types/user';
import { theme, Icon } from './theme';
import AssistantWidget from './AssistantWidget';

interface LayoutProps {
  children: React.ReactNode;
  user?: User;
}

const Layout: React.FC<LayoutProps> = ({ children, user }) => {
  return (
    <div
      className="min-h-screen relative overflow-x-hidden"
      style={{ background: theme.pageBackground }}
    >
      {/* Subtle circuit grid */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 opacity-[0.04] z-0"
        style={{
          backgroundImage:
            'linear-gradient(rgba(124,58,237,0.6) 1px, transparent 1px), linear-gradient(90deg, rgba(124,58,237,0.6) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />
      <Navigation user={user} />
      <main className="relative pt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">{children}</div>
      </main>
      <footer className="relative mt-12 border-t border-violet-200/40 bg-white/40 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2 text-slate-500">
            <span className="w-6 h-6 rounded-md bg-gradient-to-br from-violet-500 to-pink-500 flex items-center justify-center">
              <Icon.Shield className="w-3.5 h-3.5 text-white" />
            </span>
            OTShield &copy; 2026 · Deception-Driven OT Security
          </div>
          <p className="text-slate-400">
            Confidential &nbsp;·&nbsp; Live telemetry &nbsp;·&nbsp; www.otshield.io
          </p>
        </div>
      </footer>
      <AssistantWidget />
    </div>
  );
};

export default Layout;
