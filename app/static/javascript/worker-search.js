/**
 * Web Worker for handling expensive client-side table searches and sorting.
 * Prevents UI thread freezing on large dashboards.
 */

self.onmessage = function(e) {
  const { action, query, data, keys, sortBy, sortOrder } = e.data;
  
  try {
    if (action === 'filter') {
      const q = (query || "").toLowerCase();
      
      const filtered = data.filter(row => {
        // If no specific keys provided, search all string values
        if (!keys || keys.length === 0) {
          return Object.values(row).some(val => 
            String(val).toLowerCase().includes(q)
          );
        }
        
        // Search specific keys
        return keys.some(key => 
          String(row[key] || "").toLowerCase().includes(q)
        );
      });
      
      self.postMessage({ status: 'success', result: filtered });

    } else if (action === 'sort') {
      const sorted = [...data].sort((a, b) => {
        let valA = a[sortBy];
        let valB = b[sortBy];
        
        // Handle undefined
        if (valA === undefined) valA = "";
        if (valB === undefined) valB = "";

        // Numeric sort if applicable
        const numA = Number(valA);
        const numB = Number(valB);
        if (!isNaN(numA) && !isNaN(numB)) {
          return sortOrder === 'asc' ? numA - numB : numB - numA;
        }

        // String sort
        const strA = String(valA).toLowerCase();
        const strB = String(valB).toLowerCase();
        if (strA < strB) return sortOrder === 'asc' ? -1 : 1;
        if (strA > strB) return sortOrder === 'asc' ? 1 : -1;
        return 0;
      });

      self.postMessage({ status: 'success', result: sorted });
    }
  } catch (error) {
    self.postMessage({ status: 'error', error: error.message });
  }
};
