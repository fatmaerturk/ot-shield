import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import ExecutiveDashboard from './components/ExecutiveDashboard';
import Assets from './components/Assets';
import PrivateRoute from './components/PrivateRoute';
import Anomalies from './components/Anomalies';
import Honeypot from './components/Honeypot';
import Hazop from './components/Hazop';
import MitreMatrix from './components/MitreMatrix';
import UserManagement from './components/UserManagement';
import ThreatIntelligence from './components/ThreatIntelligence';
import Alerts from './components/Alerts';
import Conpot from './components/Conpot';
import NIS2Compliance from './components/NIS2Compliance';
import NetworkTopology from './components/NetworkTopology';
import Decoy from './components/Decoy';
import ThreatIntelAttackers from './components/ThreatIntelAttackers';
import Cases from './components/Cases';
import ResearchStudio from './components/ResearchStudio';
import { BundleProvider } from './contexts/BundleContext';
import { AppModeProvider, useAppMode } from './contexts/AppModeContext';

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
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/executive" element={<PrivateRoute><ExecutiveDashboard/></PrivateRoute>} />
          <Route path="/dashboard" element={<PrivateRoute><Dashboard/></PrivateRoute>} />
          <Route path="/assets" element={<PrivateRoute><Assets /></PrivateRoute>} />
          <Route path="/anomalies" element={<PrivateRoute><Anomalies /></PrivateRoute>} />
          <Route path="/alerts" element={<PrivateRoute><Alerts /></PrivateRoute>} />
          <Route path="/honeypot" element={<PrivateRoute><Honeypot /></PrivateRoute>} />
          <Route path="/attack-intelligence" element={<PrivateRoute><Honeypot /></PrivateRoute>} />
          {/* Backwards-compatible redirect: keep old /otpot URLs working */}
          <Route path="/otpot" element={<Navigate to="/attack-intelligence" replace />} />
          <Route path="/hazop" element={<PrivateRoute><Hazop /></PrivateRoute>} />
          <Route path="/mitre-matrix" element={<PrivateRoute><MitreMatrix /></PrivateRoute>} />
          <Route path="/user-management" element={<PrivateRoute><UserManagement /></PrivateRoute>} />
          <Route path="/threat-intelligence" element={<PrivateRoute><ThreatIntelligence /></PrivateRoute>} />
          <Route path="/integrations/ics-decoy" element={<PrivateRoute><Conpot /></PrivateRoute>} />
          {/* Backwards-compatible redirect: keep old /integrations/conpot URLs working */}
          <Route path="/integrations/conpot" element={<Navigate to="/integrations/ics-decoy" replace />} />
          <Route path="/compliance/nis2" element={<PrivateRoute><NIS2Compliance /></PrivateRoute>} />
          <Route path="/network-topology" element={<PrivateRoute><NetworkTopology /></PrivateRoute>} />
          <Route path="/decoy" element={<PrivateRoute><Decoy /></PrivateRoute>} />
          <Route path="/threat-intel/attackers" element={<PrivateRoute><ThreatIntelAttackers /></PrivateRoute>} />
          <Route path="/cases" element={<PrivateRoute><Cases /></PrivateRoute>} />
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
      </Router>
    </AppModeProvider>
  );
};

export default App;
