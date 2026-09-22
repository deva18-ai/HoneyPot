import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { ThreatOverview } from './pages/ThreatOverview';
import { Incidents } from './pages/Incidents';
import { Events } from './pages/Events';
import { Investigation } from './pages/Investigation';
import { IPAnalysis } from './pages/IPAnalysis';
import { Services } from './pages/Services';
import { Alerts } from './pages/Alerts';
import { MITRE } from './pages/MITRE';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { useAuth } from './context/AuthContext';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-8 h-8 border-4 border-primary-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-8 h-8 border-4 border-primary-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
      
      <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/threat-overview" element={<ThreatOverview />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:id" element={<Investigation />} />
        <Route path="/events" element={<Events />} />
        <Route path="/investigation" element={<Investigation />} />
        <Route path="/ip-analysis" element={<IPAnalysis />} />
        <Route path="/services" element={<Services />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/mitre" element={<MITRE />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}