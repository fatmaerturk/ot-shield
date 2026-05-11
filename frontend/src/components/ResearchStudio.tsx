import React, { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { PageShell, PageHero, Icon } from './theme';
import LibraryTab from './research/LibraryTab';
import ThreadsTab from './research/ThreadsTab';
import FindingsTab from './research/FindingsTab';
import VulnsTab from './research/VulnsTab';
import WorkspaceTab from './research/WorkspaceTab';
import SummaryTab from './research/SummaryTab';
import InventoryTab from './research/InventoryTab';
import PortsServicesTab from './research/PortsServicesTab';
import BundleSidebar from './research/BundleSidebar';
import { useBundles } from '../contexts/BundleContext';

/* ---------------------------------------------------------------------------
 * Research Studio - bundle-aware workbench
 *
 * Layout is a two-column flex: a fixed-width BundleSidebar on the left
 * (the list of parallel investigations), and a content area on the
 * right holding the five tabs (Workspace / Library / Threads / Findings
 * / Vulns). The active bundle's id is pinned to the axios request
 * interceptor so every child tab automatically queries scoped data.
 * ------------------------------------------------------------------------ */

type TabKey = 'workspace' | 'library' | 'summary' | 'inventory' | 'ports' | 'threads' | 'findings' | 'vulns';

interface TabDef {
  key: TabKey;
  path: string;
  label: string;
  hint: string;
  icon: React.ReactNode;
}

const TABS: TabDef[] = [
  {
    key: 'workspace',
    path: '/research/workspace',
    label: 'Workspace',
    hint: 'Bundle settings: tags, watch folder, snapshot export',
    icon: <Icon.Layers className="w-4 h-4" />,
  },
  {
    key: 'library',
    path: '/research/library',
    label: 'Library',
    hint: 'Upload and index source material',
    icon: <Icon.Server className="w-4 h-4" />,
  },
  {
    key: 'summary',
    path: '/research/summary',
    label: 'Summary',
    hint: 'LLM-generated technical summary of this bundle\'s product and components',
    icon: <Icon.Bolt className="w-4 h-4" />,
  },
  {
    key: 'inventory',
    path: '/research/inventory',
    label: 'Inventory',
    hint: 'Components and protocols identified from the corpus',
    icon: <Icon.Network className="w-4 h-4" />,
  },
  {
    key: 'ports',
    path: '/research/ports',
    label: 'Ports & services',
    hint: 'Physical/logical ports and running services',
    icon: <Icon.Activity className="w-4 h-4" />,
  },
  {
    key: 'threads',
    path: '/research/threads',
    label: 'Threads',
    hint: 'Persistent copilot conversations',
    icon: <Icon.Brain className="w-4 h-4" />,
  },
  {
    key: 'findings',
    path: '/research/findings',
    label: 'Findings',
    hint: 'Curated knowledge ledger',
    icon: <Icon.CheckCircle className="w-4 h-4" />,
  },
  {
    key: 'vulns',
    path: '/research/vulns',
    label: 'Vulns',
    hint: 'Vulnerability observations - researcher-authored, offline-first',
    icon: <Icon.Shield className="w-4 h-4" />,
  },
];

const resolveActiveTab = (pathname: string): TabKey => {
  if (pathname.startsWith('/research/workspace')) return 'workspace';
  if (pathname.startsWith('/research/summary'))   return 'summary';
  if (pathname.startsWith('/research/inventory')) return 'inventory';
  if (pathname.startsWith('/research/ports'))     return 'ports';
  if (pathname.startsWith('/research/threads'))   return 'threads';
  if (pathname.startsWith('/research/findings'))  return 'findings';
  if (pathname.startsWith('/research/vulns'))     return 'vulns';
  return 'library';
};

const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const ResearchStudio: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const activeTab = useMemo(() => resolveActiveTab(location.pathname), [location.pathname]);
  const { activeBundle, activeBundleId, loading: bundleLoading } = useBundles();
  const [libraryStats, setLibraryStats] = useState<{ total: number; ready: number; chunks: number; bytes: number }>(
    { total: 0, ready: 0, chunks: 0, bytes: 0 }
  );

  useEffect(() => {
    const suffix = activeBundle ? ` · ${activeBundle.name}` : '';
    document.title = `OTShield · Research · ${activeTab}${suffix}`;
  }, [activeTab, activeBundle]);

  return (
    <PageShell>
      <PageHero
        eyebrow="RESEARCH STUDIO"
        icon={<Icon.Brain className="w-3.5 h-3.5" />}
        title={
          <span>
            Research Workbench
            {activeBundle && (
              <span className="ml-3 text-base font-semibold text-violet-600">
                · {activeBundle.name}
              </span>
            )}
          </span>
        }
        subtitle="A single place to feed the copilot, run investigations, and capture curated findings. Bundles keep parallel teardowns cleanly separated; everything you upload, ask, or promote lives inside the active bundle."
        stats={[
          { label: 'Documents', value: libraryStats.total, sub: `${libraryStats.ready} ready` },
          { label: 'Indexed chunks', value: libraryStats.chunks, sub: 'across all documents' },
          { label: 'Storage', value: formatBytes(libraryStats.bytes), sub: 'local only' },
        ]}
      />

      {/* Tab bar */}
      <div className="mb-6">
        <div className="flex flex-wrap gap-2 p-1.5 rounded-2xl bg-white ring-1 ring-slate-200 w-fit">
          {TABS.map((t) => {
            const active = t.key === activeTab;
            return (
              <button
                key={t.key}
                type="button"
                onClick={() => navigate(t.path)}
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition ${
                  active
                    ? 'bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white shadow-md shadow-violet-500/30'
                    : 'text-slate-600 hover:bg-slate-50'
                }`}
              >
                <span className={active ? 'text-white' : 'text-violet-500'}>{t.icon}</span>
                {t.label}
              </button>
            );
          })}
        </div>
        <div className="mt-2 text-xs text-slate-500">
          {TABS.find((t) => t.key === activeTab)?.hint}
        </div>
      </div>

      {/* Two-column layout: bundle sidebar | tab body */}
      <div className="flex gap-4 items-start">
        <BundleSidebar className="w-72 flex-shrink-0 max-h-[calc(100vh-14rem)]" />

        <div className="flex-1 min-w-0">
          {/* No-bundle guard: render a lightweight prompt instead of
              leaving children to awkwardly deal with a null active id. */}
          {!activeBundleId && !bundleLoading && (
            <div className="bg-white rounded-2xl ring-1 ring-slate-200 p-8 text-center">
              <div className="mx-auto w-12 h-12 rounded-xl bg-slate-100 text-slate-400 flex items-center justify-center mb-3">
                <Icon.Layers className="w-6 h-6" />
              </div>
              <div className="text-sm font-semibold text-slate-700">No bundle selected</div>
              <div className="text-xs text-slate-500 mt-1">
                Create or pick a bundle on the left to start working.
              </div>
            </div>
          )}

          {/* Keying tab children by activeBundleId forces a remount when
              the researcher switches workspaces - avoids having to thread
              an "active bundle changed" signal through every tab's local
              state. */}
          {activeBundleId && (
            <div key={activeBundleId}>
              {activeTab === 'workspace' && <WorkspaceTab />}
              {activeTab === 'library'   && <LibraryTab onStatsChange={setLibraryStats} />}
              {activeTab === 'summary'   && <SummaryTab />}
              {activeTab === 'inventory' && <InventoryTab />}
              {activeTab === 'ports'     && <PortsServicesTab />}
              {activeTab === 'threads'   && <ThreadsTab />}
              {activeTab === 'findings'  && <FindingsTab />}
              {activeTab === 'vulns'     && <VulnsTab />}
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
};

export default ResearchStudio;
