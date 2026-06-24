/**
 * ErrorBoundary — catches unhandled React render errors.
 * Wrap page-level components to prevent the entire UI from crashing.
 *
 * Usage:
 *   <ErrorBoundary>
 *     <DashboardPage />
 *   </ErrorBoundary>
 */
import { Component } from 'react';

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    // In production, send to your error tracking service
    console.error('[ErrorBoundary]', error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '60vh',
          gap: '1rem',
          color: 'var(--color-text-primary, #1a1a1a)',
        }}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth="1.5" style={{ opacity: 0.4 }}>
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <h2 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 500 }}>
            Something went wrong
          </h2>
          <p style={{ margin: 0, opacity: 0.6, fontSize: '0.9rem' }}>
            {this.state.error?.message || 'An unexpected error occurred'}
          </p>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              padding: '0.5rem 1.5rem',
              borderRadius: '6px',
              border: '1px solid currentColor',
              background: 'transparent',
              cursor: 'pointer',
              fontSize: '0.9rem',
            }}
          >
            Try again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
