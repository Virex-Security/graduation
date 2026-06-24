/**
 * useApiRequest — standardized hook for API calls with loading/error state.
 * Eliminates repetitive try/catch blocks across page components.
 *
 * Usage:
 *   const { data, loading, error, execute } = useApiRequest(
 *     () => API.get('/dashboard/data')
 *   );
 */
import { useState, useCallback } from 'react';

export function useApiRequest(apiFn, { onSuccess, onError } = {}) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const execute = useCallback(async (...args) => {
    setLoading(true);
    setError(null);
    try {
      const result = await apiFn(...args);
      setData(result);
      onSuccess?.(result);
      return result;
    } catch (err) {
      const message = err.message || 'Request failed';
      setError(message);
      onError?.(message);
      return null;
    } finally {
      setLoading(false);
    }
  }, [apiFn, onSuccess, onError]);

  return { data, loading, error, execute };
}
