import React, { useState, useMemo, useCallback } from 'react';
import { ChevronUpIcon, ChevronDownIcon, MagnifyingGlassIcon, ChevronLeftIcon, ChevronRightIcon } from '@heroicons/react/24/outline';
import { IconButton } from './Buttons';

/** Severity/Status badge */
export function Badge({ label, className = '' }) {
  return (
    <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wide border ${className}`}>
      {label}
    </span>
  );
}

/**
 * DataTable — sortable, filterable, paginated table.
 *
 * columns: [{ key, label, render?, sortable?, className? }]
 * data: array of row objects
 * pageSize: rows per page (default 10)
 * searchable: show search bar
 * emptyMessage: override empty state text
 * loading: show skeleton rows
 */
export default function DataTable({
  columns = [],
  data = [],
  pageSize = 10,
  searchable = true,
  emptyMessage = 'No data found',
  loading = false,
  caption,
}) {
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState(null);
  const [sortDir, setSortDir] = useState('asc');
  const [page, setPage] = useState(1);

  const handleSort = useCallback((key) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
    setPage(1);
  }, [sortKey]);

  const filtered = useMemo(() => {
    if (!search.trim()) return data;
    const q = search.toLowerCase();
    return data.filter((row) =>
      columns.some((col) => {
        const val = row[col.key];
        return val !== null && val !== undefined && String(val).toLowerCase().includes(q);
      })
    );
  }, [data, search, columns]);

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    return [...filtered].sort((a, b) => {
      const va = a[sortKey] ?? '';
      const vb = b[sortKey] ?? '';
      const cmp = String(va).localeCompare(String(vb), undefined, { numeric: true });
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const paginated = sorted.slice((page - 1) * pageSize, page * pageSize);

  const handleSearch = useCallback((e) => {
    setSearch(e.target.value);
    setPage(1);
  }, []);

  const skeletonRows = Array.from({ length: pageSize });

  return (
    <div className="flex flex-col gap-4">
      {/* Search */}
      {searchable && (
        <div className="relative">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" aria-hidden="true" />
          <input
            type="search"
            placeholder="Search…"
            value={search}
            onChange={handleSearch}
            aria-label="Search table"
            className="form-input pl-9 w-full sm:w-72"
          />
        </div>
      )}

      {/* Announce search result count to screen readers */}
      <div role="status" className="sr-only" aria-live="polite">
        {!loading && `${sorted.length} result${sorted.length !== 1 ? 's' : ''} found`}
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-border-dim">
        <table className="w-full text-sm" role="table">
          {caption && <caption className="sr-only">{caption}</caption>}
          <thead>
            <tr className="border-b border-border-dim bg-bg-secondary/50">
              {columns.map((col) => (
                <th
                  key={col.key}
                  scope="col"
                  className={`px-4 py-3 text-left text-xs font-semibold text-text-muted uppercase tracking-wider whitespace-nowrap ${col.className || ''}`}
                >
                  {col.sortable !== false ? (
                    <button
                      onClick={() => handleSort(col.key)}
                      className="flex items-center gap-1 hover:text-text-primary transition-colors"
                      aria-label={`Sort by ${col.label}${sortKey === col.key ? (sortDir === 'asc' ? ', ascending' : ', descending') : ''}`}
                    >
                      {col.label}
                      <span aria-hidden="true" className="flex flex-col -space-y-1">
                        <ChevronUpIcon className={`w-3 h-3 ${sortKey === col.key && sortDir === 'asc' ? 'text-brand-primary' : 'opacity-30'}`} />
                        <ChevronDownIcon className={`w-3 h-3 ${sortKey === col.key && sortDir === 'desc' ? 'text-brand-primary' : 'opacity-30'}`} />
                      </span>
                    </button>
                  ) : (
                    col.label
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              skeletonRows.map((_, i) => (
                <tr key={i} className="border-b border-border-dim/50">
                  {columns.map((col) => (
                    <td key={col.key} className="px-4 py-3">
                      <div className="h-4 bg-bg-secondary rounded animate-pulse" style={{ width: `${60 + (i * col.key.length) % 30}%` }} />
                    </td>
                  ))}
                </tr>
              ))
            ) : paginated.length === 0 ? (
              <tr>
                <td colSpan={columns.length}>
                  <div className="flex flex-col items-center justify-center py-16 text-text-muted gap-3">
                    <svg className="w-12 h-12 opacity-30" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 012-2h2a2 2 0 012 2M9 5h6" />
                    </svg>
                    <p className="text-sm">{emptyMessage}</p>
                  </div>
                </td>
              </tr>
            ) : (
              paginated.map((row, i) => (
                <tr
                  key={row.id ?? i}
                  className="border-b border-border-dim/50 hover:bg-bg-secondary/40 transition-colors"
                >
                  {columns.map((col) => (
                    <td key={col.key} className={`px-4 py-3 text-text-secondary align-middle ${col.className || ''}`}>
                      {col.render ? col.render(row[col.key], row) : (row[col.key] ?? '—')}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {!loading && sorted.length > pageSize && (
        <div className="flex items-center justify-between text-sm text-text-muted flex-wrap gap-2">
          <span>
            Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, sorted.length)} of {sorted.length}
          </span>
          <div className="flex items-center gap-1">
            <IconButton
              label="Previous page"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              <ChevronLeftIcon className="w-4 h-4" />
            </IconButton>
            {Array.from({ length: totalPages }, (_, i) => i + 1)
              .filter((p) => p === 1 || p === totalPages || Math.abs(p - page) <= 1)
              .reduce((acc, p, i, arr) => {
                if (i > 0 && p - arr[i - 1] > 1) acc.push('…');
                acc.push(p);
                return acc;
              }, [])
              .map((p, i) =>
                p === '…' ? (
                  <span key={`ellipsis-${i}`} className="px-2 text-text-muted">…</span>
                ) : (
                  <button
                    key={p}
                    onClick={() => setPage(p)}
                    aria-label={`Page ${p}`}
                    aria-current={p === page ? 'page' : undefined}
                    className={`w-8 h-8 rounded-lg text-sm font-medium transition-colors ${
                      p === page
                        ? 'bg-brand-primary text-white'
                        : 'hover:bg-bg-secondary text-text-secondary'
                    }`}
                  >
                    {p}
                  </button>
                )
              )}
            <IconButton
              label="Next page"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
            >
              <ChevronRightIcon className="w-4 h-4" />
            </IconButton>
          </div>
        </div>
      )}
    </div>
  );
}
