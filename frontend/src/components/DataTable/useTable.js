import { useState, useMemo, useCallback, useEffect } from 'react';
import { useFilters, filterRowsByConfig } from './useFilters';

/**
 * Client-side search, advanced filters, sort, and pagination.
 *
 * @param {object} opts
 * @param {object[]} [opts.data]
 * @param {object[]} [opts.columns]
 * @param {object[]} [opts.filterConfig]
 * @param {number} [opts.defaultPageSize]
 * @param {string[]} [opts.searchKeys] — row keys to include in global search (default: all column keys)
 */
export function useTable({
  data = [],
  columns = [],
  filterConfig = [],
  defaultPageSize = 10,
  searchKeys,
}) {
  const { values: filterValues, setFilter, resetFilters } = useFilters({});
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState(null);
  const [sortDir, setSortDir] = useState('asc');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(defaultPageSize);

  const keysToSearch = useMemo(() => {
    if (searchKeys?.length) return searchKeys;
    return columns.map((c) => c.key).filter(Boolean);
  }, [columns, searchKeys]);

  const searched = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return data;
    return data.filter((row) =>
      keysToSearch.some((k) => {
        const val = row[k];
        return val != null && String(val).toLowerCase().includes(q);
      })
    );
  }, [data, search, keysToSearch]);

  const filtered = useMemo(
    () => filterRowsByConfig(searched, filterConfig, filterValues),
    [searched, filterConfig, filterValues]
  );

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    const col = columns.find((c) => c.key === sortKey);
    return [...filtered].sort((a, b) => {
      let va;
      let vb;
      if (col?.getSortValue) {
        va = col.getSortValue(a);
        vb = col.getSortValue(b);
      } else {
        va = a[sortKey];
        vb = b[sortKey];
      }
      const na = Number(va);
      const nb = Number(vb);
      let cmp;
      const sa = String(va ?? '').trim();
      const sb = String(vb ?? '').trim();
      if (sa !== '' && sb !== '' && !Number.isNaN(na) && !Number.isNaN(nb)) {
        cmp = na - nb;
      } else {
        cmp = sa.localeCompare(sb, undefined, { numeric: true, sensitivity: 'base' });
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortDir, columns]);

  const total = sorted.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize) || 1);

  useEffect(() => {
    setPage((p) => Math.min(p, pageCount));
  }, [pageCount]);

  const paginated = useMemo(() => {
    const start = (page - 1) * pageSize;
    return sorted.slice(start, start + pageSize);
  }, [sorted, page, pageSize]);

  const onSearchChange = useCallback((e) => {
    setSearch(e.target.value);
    setPage(1);
  }, []);

  const onSort = useCallback(
    (key) => {
      if (sortKey === key) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
      } else {
        setSortKey(key);
        setSortDir('asc');
      }
      setPage(1);
    },
    [sortKey]
  );

  const onPageSizeChange = useCallback((e) => {
    const next = Number(e.target.value);
    setPageSize(next);
    setPage(1);
  }, []);

  const setFilterAndResetPage = useCallback(
    (id, v) => {
      setFilter(id, v);
      setPage(1);
    },
    [setFilter]
  );

  const goPrev = useCallback(() => {
    setPage((p) => Math.max(1, p - 1));
  }, []);

  const goNext = useCallback(() => {
    setPage((p) => Math.min(pageCount, p + 1));
  }, [pageCount]);

  const goToPage = useCallback((p) => {
    setPage(Math.min(pageCount, Math.max(1, p)));
  }, [pageCount]);

  return {
    search,
    setSearch,
    onSearchChange,
    sortKey,
    sortDir,
    onSort,
    page,
    setPage,
    pageSize,
    setPageSize,
    onPageSizeChange,
    pageCount,
    total,
    paginated,
    filterValues,
    setFilter: setFilterAndResetPage,
    resetFilters,
    goPrev,
    goNext,
    goToPage,
  };
}

export default useTable;
