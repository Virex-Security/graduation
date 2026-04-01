import React, { lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './utils/AuthContext';
import { useAuth } from './utils/useAuth';
import { ToastProvider } from './utils/ToastContext';
import ErrorBoundary from './components/ErrorBoundary';
import DashboardLayout from './layouts/DashboardLayout';
import { SecondaryButton } from './components/Buttons';

// Lazy-load all pages for code splitting
const LoginPage = lazy(() => import('./pages/LoginPage'));
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const AttacksPage = lazy(() => import('./pages/AttacksPage'));
const IncidentsPage = lazy(() => import('./pages/IncidentsPage'));
const IncidentDetailPage = lazy(() => import('./pages/IncidentDetailPage'));
const ForgotPasswordPage = lazy(() => import('./pages/ForgotPasswordPage'));
const RequestsPage = lazy(() => import('./pages/RequestsPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const BlacklistPage = lazy(() => import('./pages/BlacklistPage'));
const UserManagerPage = lazy(() => import('./pages/UserManagerPage'));
const MLDetectionsPage = lazy(() => import('./pages/MLDetectionsPage'));
const MLPerformancePage = lazy(() => import('./pages/MLPerformancePage'));
const PricingPage = lazy(() => import('./pages/PricingPage'));

// Route guard: redirect to /login if not authenticated
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-bg-main flex items-center justify-center">
        <div className="w-10 h-10 rounded-full border-2 border-brand-primary border-t-transparent animate-spin" aria-label="Loading" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrowserRouter>
          <ErrorBoundary>
            <Routes>
              {/* Public routes */}
              <Route path="/login" element={<LoginPage />} />
              <Route path="/forgot-password" element={<ForgotPasswordPage />} />

              {/* Protected dashboard routes */}
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <DashboardLayout />
                  </ProtectedRoute>
                }
              >
                <Route index element={<Navigate to="/dashboard" replace />} />
                <Route path="dashboard" element={<ErrorBoundary><DashboardPage /></ErrorBoundary>} />
                <Route path="incidents" element={<ErrorBoundary><IncidentsPage /></ErrorBoundary>} />
                <Route path="incidents/:id" element={<ErrorBoundary><IncidentDetailPage /></ErrorBoundary>} />
                <Route path="attack-history" element={<ErrorBoundary><AttacksPage /></ErrorBoundary>} />
                <Route path="ml-detections" element={<ErrorBoundary><MLDetectionsPage /></ErrorBoundary>} />
                <Route path="ml-performance" element={<ErrorBoundary><MLPerformancePage /></ErrorBoundary>} />
                <Route path="requests" element={<ErrorBoundary><RequestsPage /></ErrorBoundary>} />
                <Route path="pricing" element={<ErrorBoundary><PricingPage /></ErrorBoundary>} />
                <Route path="settings" element={<ErrorBoundary><SettingsPage /></ErrorBoundary>} />
                
                {/* Admin-only routes (AuthContext handles role checks inside components) */}
                <Route path="user-manager" element={<ErrorBoundary><UserManagerPage /></ErrorBoundary>} />
                <Route path="blacklist" element={<ErrorBoundary><BlacklistPage /></ErrorBoundary>} />
                
                {/* Fallback navigation for sidebar links that might be slightly different */}
                <Route path="blocked" element={<Navigate to="/blacklist" replace />} />
                <Route path="critical" element={<Navigate to="/incidents" replace />} />

                {/* Fallthrough */}
                <Route path="*" element={
                  <div className="flex flex-col items-center justify-center h-full gap-4">
                    <h1 className="text-4xl font-black text-text-muted">404</h1>
                    <p className="text-text-secondary">Page not found.</p>
                    <SecondaryButton onClick={() => window.location.href = '/dashboard'}>Go to Dashboard</SecondaryButton>
                  </div>
                } />
              </Route>

              <Route path="*" element={<Navigate to="/login" replace />} />
            </Routes>
          </ErrorBoundary>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
}
