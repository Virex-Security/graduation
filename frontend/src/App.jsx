import React, { useState, useEffect } from 'react';

export default function App() {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const handleMessage = (event) => {
      if (event.data && event.data.type === 'SHOW_LOADER') {
        setLoading(true);
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  return (
    <div style={{ position: 'relative', width: '100vw', height: '100vh', backgroundColor: '#191c2b', overflow: 'hidden' }}>
      {loading && (
        <div className="global-loader-container">
          <div className="global-loader-ring"></div>
          <div className="global-loader-v" style={{ position: 'absolute' }}>
            <svg viewBox="15 0 70 100" style={{ width: '60px', height: '60px' }}>
              <defs>
                <linearGradient id="loader-v-left" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" style={{ stopColor: '#9a277d' }}></stop>
                  <stop offset="100%" style={{ stopColor: '#792b9d' }}></stop>
                </linearGradient>
                <linearGradient id="loader-v-right" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" style={{ stopColor: '#e046ba' }}></stop>
                  <stop offset="100%" style={{ stopColor: '#b347e6' }}></stop>
                </linearGradient>
              </defs>
              <path d="M25,25 L50,80" stroke="url(#loader-v-left)" strokeWidth="20" strokeLinecap="round" fill="none"></path>
              <path d="M50,80 L75,25" stroke="url(#loader-v-right)" strokeWidth="20" strokeLinecap="round" fill="none"></path>
            </svg>
          </div>
        </div>
      )}
      <iframe
        src={"http://localhost:8090" + window.location.pathname + window.location.search + window.location.hash}
        style={{ 
          width: '100%', 
          height: '100%', 
          border: 'none', 
          display: 'block',
          opacity: loading ? 0 : 1,
          transition: 'opacity 0.4s ease-in-out'
        }}
        onLoad={() => setLoading(false)}
        title="VIREX Secure Application"
      />
    </div>
  );
}
