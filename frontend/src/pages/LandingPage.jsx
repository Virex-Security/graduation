import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../utils/useAuth';
import './LandingPage.css';

export default function LandingPage() {
  const navigate = useNavigate();
  const { user, loading } = useAuth();

  // Redirect logged in users
  useEffect(() => {
    if (!loading && user) {
      navigate('/dashboard', { replace: true });
    }
  }, [user, loading, navigate]);

  const toggleTheme = () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    document.documentElement.setAttribute('data-theme', isDark ? 'light' : 'dark');
    if (isDark) {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  };

  if (loading) return null; // Avoid flicker while checking auth state

  return (
    <div className="landing-page">
      {/* Navbar */}
      <nav className="navbar">
        <div className="navbar-container">
          <div className="logo" onClick={() => navigate('/')} style={{ cursor: 'pointer', gap: 0 }}>
            <svg className="brand-v-nav" viewBox="10 0 70 100" style={{ width: '40px', height: '40px' }}>
              <defs>
                <linearGradient id="v-nav-left-login" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" style={{ stopColor: '#9a277d' }}></stop>
                  <stop offset="100%" style={{ stopColor: '#792b9d' }}></stop>
                </linearGradient>
                <linearGradient id="v-nav-right-login" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" style={{ stopColor: '#e046ba' }}></stop>
                  <stop offset="100%" style={{ stopColor: '#b347e6' }}></stop>
                </linearGradient>
              </defs>
              <path d="M25,25 L50,80" stroke="url(#v-nav-left-login)" strokeWidth="20" strokeLinecap="round" fill="none"></path>
              <path d="M50,80 L75,25" stroke="url(#v-nav-right-login)" strokeWidth="20" strokeLinecap="round" fill="none"></path>
            </svg><span className="brand-v-icon">IREX</span>
          </div>

          <ul className="nav-menu">
            <li><a href="#features">Features</a></li>
            <li><a href="#how-it-works">How It Works</a></li>
            <li><a href="#security">Security</a></li>
            <li><a href="#">Contact Us</a></li>
          </ul>

          <div className="nav-buttons">
            <button
              className="btn-icon"
              onClick={toggleTheme}
              title="Toggle Light/Dark Mode"
            >
              <i className="fas fa-sun"></i>
            </button>
            <button className="btn-login-nav" onClick={() => navigate('/login')}>Login</button>
            <button className="btn-signup-nav" onClick={() => navigate('/login')}>
              Sign up
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="hero">
        <div className="hero-container">
          <div className="hero-content">
            <h1 className="hero-title">Real-Time API Security Monitoring</h1>
            <p className="hero-description">
              Protect your APIs from threats with real-time monitoring. Our
              advanced machine learning system detects and blocks suspicious
              activities before they impact your applications.
            </p>
            <div className="hero-buttons">
              <button
                className="btn-primary"
                onClick={() => navigate('/login')}
              >
                <span>View Security Dashboard</span>
                <i className="fas fa-arrow-right"></i>
              </button>
              <button
                className="btn-secondary"
                onClick={() => {}}
              >
                <span>Contact Us</span>
              </button>
            </div>
          </div>

          <div className="hero-visual">
            <div className="shield-container">
              <div className="shield-glow"></div>
              <div className="rotating-ring"></div>
              <div className="shield-main">
                <svg className="brand-v-svg" viewBox="0 0 100 100">
                  <defs>
                    <linearGradient id="v-gradient-left" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="0%" style={{ stopColor: '#9a277d' }} />
                      <stop offset="100%" style={{ stopColor: '#792b9d' }} />
                    </linearGradient>
                    <linearGradient id="v-gradient-right" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="0%" style={{ stopColor: '#e046ba' }} />
                      <stop offset="100%" style={{ stopColor: '#b347e6' }} />
                    </linearGradient>
                  </defs>
                  <path className="v-path-left" d="M25,25 L50,80" />
                  <path className="v-path-right" d="M50,80 L75,25" />
                </svg>
              </div>
            </div>

            <div className="floating-card card-1">
              <div className="card-icon">
                <i className="fas fa-chart-line"></i>
              </div>
              <div className="card-content">
                <h4>Real-Time Analytics</h4>
                <p>Monitor threats instantly</p>
              </div>
            </div>

            <div className="floating-card card-2">
              <div className="card-icon">
                <i className="fas fa-lock"></i>
              </div>
              <div className="card-content">
                <h4>Advanced Protection</h4>
                <p>ML-powered security</p>
              </div>
            </div>

            <div className="floating-card card-3">
              <div className="card-icon">
                <i className="fas fa-bell"></i>
              </div>
              <div className="card-content">
                <h4>Instant Alerts</h4>
                <p>Get notified immediately</p>
              </div>
            </div>

            <div className="floating-card card-4">
              <div className="card-icon">
                <i className="fas fa-database"></i>
              </div>
              <div className="card-content">
                <h4>Data Insights</h4>
                <p>Comprehensive reports</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="features" id="features">
        <div className="features-container">
          <div className="section-header">
            <div className="section-eyebrow">Our Features</div>
            <h2 className="section-title">Comprehensive Security Solutions</h2>
            <p className="section-description">
              VIREX provides enterprise-grade security monitoring with advanced
              machine learning capabilities to protect your APIs and applications.
            </p>
          </div>

          <div className="features-grid">
            <div className="feature-card">
              <div className="feature-icon">
                <i className="fas fa-shield-virus"></i>
              </div>
              <h3 className="feature-title">Threat Detection</h3>
              <p className="feature-description">
                Advanced ML algorithms detect SQL injection, XSS, and other attack
                patterns in real-time with 99%+ accuracy.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">
                <i className="fas fa-chart-line"></i>
              </div>
              <h3 className="feature-title">Real-Time Monitoring</h3>
              <p className="feature-description">
                Monitor all API requests and responses with live dashboards
                showing security metrics and threat levels.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">
                <i className="fas fa-brain"></i>
              </div>
              <h3 className="feature-title">Machine Learning</h3>
              <p className="feature-description">
                Self-learning system that adapts to new threats and improves
                detection accuracy over time.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">
                <i className="fas fa-bell"></i>
              </div>
              <h3 className="feature-title">Instant Alerts</h3>
              <p className="feature-description">
                Get immediate notifications via email, Slack, or webhook when
                critical threats are detected.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">
                <i className="fas fa-file-alt"></i>
              </div>
              <h3 className="feature-title">Detailed Reports</h3>
              <p className="feature-description">
                Generate comprehensive security reports with incident timelines,
                attack patterns, and remediation steps.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">
                <i className="fas fa-users-cog"></i>
              </div>
              <h3 className="feature-title">Team Management</h3>
              <p className="feature-description">
                Role-based access control with admin, analyst, and viewer
                permissions for your security team.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section className="how-it-works" id="how-it-works">
        <div className="how-it-works-container">
          <div className="section-header">
            <div className="section-eyebrow">How It Works</div>
            <h2 className="section-title">Simple 3-Step Process</h2>
            <p className="section-description">
              Get started with VIREX in minutes and protect your APIs immediately.
            </p>
          </div>

          <div className="steps-grid">
            <div className="step-card">
              <div className="step-number">1</div>
              <div className="step-icon">
                <i className="fas fa-plug"></i>
              </div>
              <h3 className="step-title">Connect Your APIs</h3>
              <p className="step-description">
                Integrate VIREX with your existing APIs using our simple SDK or proxy setup.
              </p>
            </div>

            <div className="step-card">
              <div className="step-number">2</div>
              <div className="step-icon">
                <i className="fas fa-cogs"></i>
              </div>
              <h3 className="step-title">Configure Rules</h3>
              <p className="step-description">
                Set up security rules and thresholds based on your application requirements.
              </p>
            </div>

            <div className="step-card">
              <div className="step-number">3</div>
              <div className="step-icon">
                <span className="brand-v-icon" style={{ fontSize: '2.2rem' }}>V</span>
              </div>
              <h3 className="step-title">Monitor & Protect</h3>
              <p className="step-description">
                Watch real-time threats being detected and blocked automatically.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Security Section */}
      <section className="security-section" id="security">
        <div className="security-container">
          <div className="section-header">
            <div className="section-eyebrow">Security First</div>
            <h2 className="section-title">Enterprise-Grade Protection</h2>
            <p className="section-description">
              Built with security best practices and compliance standards in mind.
            </p>
          </div>

          <div className="security-grid">
            <div className="security-card">
              <div className="security-icon">
                <i className="fas fa-lock"></i>
              </div>
              <h3 className="security-title">End-to-End Encryption</h3>
              <p className="security-description">
                All data is encrypted in transit and at rest using AES-256 encryption.
              </p>
            </div>

            <div className="security-card">
              <div className="security-icon">
                <i className="fas fa-certificate"></i>
              </div>
              <h3 className="security-title">SOC 2 Compliant</h3>
              <p className="security-description">
                Certified for security, availability, and confidentiality controls.
              </p>
            </div>

            <div className="security-card">
              <div className="security-icon">
                 <span className="brand-v-icon" style={{ fontSize: '2.2rem' }}>V</span>
              </div>
              <h3 className="security-title">Zero Trust Architecture</h3>
              <p className="security-description">
                Built on zero trust principles with multi-factor authentication.
              </p>
            </div>

            <div className="security-card">
              <div className="security-icon">
                <i className="fas fa-eye"></i>
              </div>
              <h3 className="security-title">Privacy by Design</h3>
              <p className="security-description">
                No sensitive data is stored, only security metadata and patterns.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section">
        <div className="cta-container">
          <h2 className="cta-title">Ready to Secure Your APIs?</h2>
          <p className="cta-description">
            Join hundreds of companies protecting their applications with VIREX.
            Start monitoring your API security today with our powerful platform.
          </p>
          <button className="btn-cta" onClick={() => navigate('/login')}>
            <span>Start Free Trial Now</span>
            <i className="fas fa-arrow-right"></i>
          </button>
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <div className="footer-content">
          <div className="footer-text">
            © 2026 VIREX Security. All rights reserved.
          </div>
          <div className="footer-links">
            <a href="#" className="footer-link">Privacy Policy</a>
            <a href="#" className="footer-link">Terms of Service</a>
            <a href="#" className="footer-link">Documentation</a>
            <a href="#" className="footer-link">Support</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
