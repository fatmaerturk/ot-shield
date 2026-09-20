import React, { Suspense, lazy } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import PrivateRoute from './components/PrivateRoute';
import { BundleProvider } from './contexts/BundleContext';
import { AppModeProvider, useAppMode } from './contexts/AppModeContext';

// Route-level code splitting: each page (and its heavy deps - Leaflet maps,
// Chart.js, etc.) ships as its own chunk that loads on demand, so the initial
// bundle is just the shell + Login. Login and PrivateRoute stay eager because
// they gate the very first paint. Chunks are content-hashed and served with a
// 1-year immutable Cache-Control (see nginx.conf), so each loads at most once.
const Dashboard = lazy(() => import('./components/Dashboard'));
const ExecutiveDashboard = lazy(() => import('./components/ExecutiveDashboard'));
const Assets = lazy(() => import('./components/Assets'));
const Anomalies = lazy(() => import('./components/Anomalies'));
const AttackerCampaigns = lazy(() => import('./components/AttackerCampaigns'));
const Honeypot = lazy(() => import('./components/Honeypot'));
const MitreMatrix = lazy(() => import('./components/MitreMatrix'));
const Settings = lazy(() => import('./components/Settings'));
const ThreatIntelligence = lazy(() => import('./components/ThreatIntelligence'));
const Alerts = lazy(() => import('./components/Alerts'));
const Conpot = lazy(() => import('./components/Conpot'));
const NIS2Compliance = lazy(() => import('./components/NIS2Compliance'));
const IEC62443Compliance = lazy(() => import('./components/IEC62443Compliance'));
const OutboundIntelFeed = lazy(() => import('./components/OutboundIntelFeed'));
const SiemForwarding = lazy(() => import('./components/SiemForwarding'));
const NetworkTopology = lazy(() => import('./components/NetworkTopology'));
const Decoy = lazy(() => import('./components/Decoy'));
const Honeytoken = lazy(() => import('./components/Honeytoken'));
const Engage = lazy(() => import('./components/Engage'));
const DeceptionMetrics = lazy(() => import('./components/DeceptionMetrics'));
const ThreatIntelAttackers = lazy(() => import('./components/ThreatIntelAttackers'));
const Cases = lazy(() => import('./components/Cases'));
const ResearchStudio = lazy(() => import('./components/ResearchStudio'));

/** Apply persisted theme preference before rendering routes so the
 *  user's choice survives page reloads. Reads from localStorage; falls
 *  back to the OS-level preference when set to 'system'. */
function applyPersistedTheme() {
  const saved = localStorage.getItem('themePreference');
  if (!saved) return;
  const dark =
    saved === 'dark' ||
    (saved === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  if (dark) document.documentElement.classList.add('dark');
  else document.documentElement.classList.remove('dark');
}
applyPersistedTheme();

/** Full-screen fallback shown while a route's chunk is being fetched. */
const PageLoader: React.FC = () => (
  <div className="min-h-screen flex items-center justify-center bg-slate-50">
    <div className="w-10 h-10 rounded-full border-4 border-violet-200 border-t-violet-600 animate-spin" />
  </div>
);

/** Lightweight wrapper so every Research route shares one BundleProvider instance. */
const ResearchRoute: React.FC = () => (
  <BundleProvider>
    <ResearchStudio />
  </BundleProvider>
);

/**
 * Root landing redirect that honours the app mode. RESEARCH sends the
 * user straight to the threads tab (the tear-down assistant is the
 * headline capability in that mode); SOC keeps the legacy executive
 * landing so nothing changes for the full-platform demo.
 */
const RootRedirect: React.FC = () => {
  const { mode } = useAppMode();
  return <Navigate to={mode === 'RESEARCH' ? '/research/threads' : '/executive'} replace />;
};

const App: React.FC = () => {
  return (
    <AppModeProvider>
      <Router>
        <Suspense fallback={<PageLoader />}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/executive" element={<PrivateRoute><ExecutiveDashboard/></PrivateRoute>} />
            <Route path="/dashboard" element={<PrivateRoute><Dashboard/></PrivateRoute>} />
            <Route path="/assets" element={<PrivateRoute><Assets /></PrivateRoute>} />
            <Route path="/anomalies" element={<PrivateRoute><Anomalies /></PrivateRoute>} />
            <Route path="/campaigns" element={<PrivateRoute><AttackerCampaigns /></PrivateRoute>} />
            <Route path="/alerts" element={<PrivateRoute><Alerts /></PrivateRoute>} />
            <Route path="/honeypot" element={<PrivateRoute><Honeypot /></PrivateRoute>} />
            <Route path="/attack-intelligence" element={<PrivateRoute><Honeypot /></PrivateRoute>} />
            {/* Backwards-compatible redirect: keep old /otpot URLs working */}
            <Route path="/otpot" element={<Navigate to="/attack-intelligence" replace />} />
            <Route path="/mitre-matrix" element={<PrivateRoute><MitreMatrix /></PrivateRoute>} />
            <Route path="/settings" element={<PrivateRoute><Settings /></PrivateRoute>} />
            {/* Backwards-compat: legacy /user-management URLs redirect into the unified Settings page */}
            <Route path="/user-management" element={<Navigate to="/settings" replace />} />
            <Route path="/threat-intelligence" element={<PrivateRoute><ThreatIntelligence /></PrivateRoute>} />
            <Route path="/integrations/ics-decoy" element={<PrivateRoute><Conpot /></PrivateRoute>} />
            {/* Backwards-compatible redirect: keep old /integrations/conpot URLs working */}
            <Route path="/integrations/conpot" element={<Navigate to="/integrations/ics-decoy" replace />} />
            <Route path="/compliance/nis2" element={<PrivateRoute><NIS2Compliance /></PrivateRoute>} />
            <Route path="/compliance/iec62443" element={<PrivateRoute><IEC62443Compliance /></PrivateRoute>} />
            <Route path="/network-topology" element={<PrivateRoute><NetworkTopology /></PrivateRoute>} />
            <Route path="/decoy" element={<PrivateRoute><Decoy /></PrivateRoute>} />
            <Route path="/honeytokens" element={<PrivateRoute><Honeytoken /></PrivateRoute>} />
            <Route path="/engage" element={<PrivateRoute><Engage /></PrivateRoute>} />
            <Route path="/deception-metrics" element={<PrivateRoute><DeceptionMetrics /></PrivateRoute>} />
            <Route path="/threat-intel/attackers" element={<PrivateRoute><ThreatIntelAttackers /></PrivateRoute>} />
            <Route path="/threat-intel/feed" element={<PrivateRoute><OutboundIntelFeed /></PrivateRoute>} />
            <Route path="/cases" element={<PrivateRoute><Cases /></PrivateRoute>} />
            <Route path="/integrations/siem" element={<PrivateRoute><SiemForwarding /></PrivateRoute>} />
            <Route path="/research/library" element={<PrivateRoute><ResearchRoute /></PrivateRoute>} />
            <Route path="/research/threads" element={<PrivateRoute><ResearchRoute /></PrivateRoute>} />
            <Route path="/research/findings" element={<PrivateRoute><ResearchRoute /></PrivateRoute>} />
            <Route path="/research/vulns" element={<PrivateRoute><ResearchRoute /></PrivateRoute>} />
            <Route path="/research/workspace" element={<PrivateRoute><ResearchRoute /></PrivateRoute>} />
            <Route path="/research/summary" element={<PrivateRoute><ResearchRoute /></PrivateRoute>} />
            <Route path="/research/inventory" element={<PrivateRoute><ResearchRoute /></PrivateRoute>} />
            <Route path="/research/ports" element={<PrivateRoute><ResearchRoute /></PrivateRoute>} />
            <Route path="/" element={<RootRedirect />} />
          </Routes>
        </Suspense>
      </Router>
    </AppModeProvider>
  );
};

export default App;
