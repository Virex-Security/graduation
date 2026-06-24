import React, { useState, useEffect } from 'react';
import apiService from '../api/apiService';

const FlaskTest = () => {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch data from health endpoint
        const response = await apiService.get('/health');
        setData(response.data);
        setError(null);
      } catch (err) {
        setError(err.message || 'Error connecting to Flask API');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  return (
    <div style={{ padding: '20px', margin: '20px', border: '1px solid #4a5568', borderRadius: '8px', backgroundColor: '#1a202c', color: '#e2e8f0' }}>
      <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', marginBottom: '16px' }}>🔌 Flask Backend Connection Test</h3>
      {loading && <p>Loading data from Flask...</p>}
      {error && <p style={{ color: '#fc8181' }}>❌ Error: {error}</p>}
      {data && (
        <div>
          <p style={{ color: '#68d391', marginBottom: '12px' }}>✅ Successfully connected to Flask via Axios!</p>
          <pre style={{ background: '#2d3748', padding: '16px', borderRadius: '4px', overflowX: 'auto', fontSize: '0.875rem' }}>
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

export default FlaskTest;
