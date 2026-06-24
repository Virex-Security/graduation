import { useState, useCallback } from 'react';

/**
 * Holds selected values keyed by filter `id`.
 * @param {Record<string, unknown>} [initialValues]
 */
export function useFilters(initialValues = {}) {
  const [values, setValues] = useState(initialValues);

  const setFilter = useCallback((id, value) => {
    setValues((prev) => ({ ...prev, [id]: value }));
  }, []);

  const resetFilters = useCallback(() => {
    setValues(initialValues);
  }, [initialValues]);

  return { values, setFilter, resetFilters, setValues };
}

/**
 * Apply advanced filters (AND). Empty / undefined / null selected values skip that filter.
 * @param {object[]} rows
 * @param {FilterConfig[]} [filterConfig]
 * @param {Record<string, unknown>} filterValues
 */
export function filterRowsByConfig(rows, filterConfig, filterValues) {
  if (!filterConfig?.length) return rows;

  return rows.filter((row) => {
    for (const cfg of filterConfig) {
      const sel = filterValues[cfg.id];
      if (sel === undefined || sel === null || sel === '') continue;

      if (typeof cfg.match === 'function') {
        if (!cfg.match(row, sel)) return false;
        continue;
      }

      const field = cfg.field ?? cfg.id;
      const raw = row[field];

      if (typeof sel === 'boolean') {
        if (Boolean(raw) !== sel) return false;
      } else {
        if (String(raw ?? '') !== String(sel)) return false;
      }
    }
    return true;
  });
}
