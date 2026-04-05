import React, { memo, useMemo, useCallback } from 'react';
import {
  ChevronUpIcon,
  ChevronDownIcon,
  MagnifyingGlassIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  FunnelIcon,
} from '@heroicons/react/24/outline';
import { IconButton } from '../Buttons';
import useTable from './useTable';

function renderCell(col, row) {
  const v = row[col.key];
  if (typeof col.render === 'function') {
    return col.render(v, row);
  }
  return v ?? '—';
}

const SearchField = memo(function SearchField({ value, onChange, placeholder, id }) {
  return (
    <div className="relative w-full min-w-0 sm:max-w-xs flex-1">
      <MagnifyingGlassIcon
        className="absolute left-ds-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none"
        aria-hidden
      />
      <input
        id={id}
        type="search"
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        aria-label="Search table"
        className="form-input pl-9 w-full"
      />
    </div>
  );
});

const FilterBar = memo(function FilterBar({ filterConfig, filterValues, onFilterChange, onReset, showReset }) {
  if (!filterConfig?.length) return null;

  return (
    <div className="flex flex-col gap-ds-3 sm:flex-row sm:flex-wrap sm:items-end w-full">
      <div className="flex items-center gap-ds-2 text-ds-caption font-semibold text-text-muted uppercase tracking-ds-wider sm:w-full lg:w-auto">
        <FunnelIcon className="w-4 h-4 text-brand-primary shrink-0" aria-hidden />
        <span>Filters</span>
      </div>
      <div className="flex flex-col sm:flex-row flex-wrap gap-ds-3 flex-1 min-w-0">
        {filterConfig.map((cfg) => (
          <div key={cfg.id} className="flex flex-col gap-ds-1 min-w-[140px] flex-1 sm:flex-none sm:min-w-[160px]">
            <label htmlFor={`dt-filter-${cfg.id}`} className="text-ds-micro text-text-muted font-medium">
              {cfg.label}
            </label>
            <select
              id={`dt-filter-${cfg.id}`}
              value={
                filterValues[cfg.id] === undefined || filterValues[cfg.id] === null
                  ? ''
                  : String(filterValues[cfg.id])
              }
              onChange={(e) => {
                const raw = e.target.value;
                const opt = cfg.options.find((o) => String(o.value) === raw);
                onFilterChange(cfg.id, opt ? opt.value : '');
              }}
              className="form-input py-ds-2 text-ds-caption"
              aria-label={cfg.label}
            >
              {cfg.options.map((opt) => (
                <option key={String(opt.value)} value={String(opt.value)}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        ))}
      </div>
      {showReset ? (
        <button
          type="button"
          onClick={onReset}
          className="text-ds-caption font-medium text-brand-primary hover:text-brand-secondary self-start sm:self-end py-ds-2"
        >
          Clear filters
        </button>
      ) : null}
    </div>
  );
});

const PageSizeSelect = memo(function PageSizeSelect({ id, value, options, onChange, disabled }) {
  return (
    <div className="flex items-center gap-ds-2">
      <label htmlFor={id} className="text-ds-caption text-text-muted whitespace-nowrap">
        Rows per page
      </label>
      <select
        id={id}
        value={String(value)}
        onChange={onChange}
        disabled={disabled}
        className="form-input py-ds-2 pr-8 text-ds-caption min-w-[4.5rem]"
        aria-label="Rows per page"
      >
        {options.map((n) => (
          <option key={n} value={n}>
            {n}
          </option>
        ))}
      </select>
    </div>
  );
});

const PaginationFooter = memo(function PaginationFooter({
  page,
  pageCount,
  total,
  pageSize,
  onPrev,
  onNext,
  onPage,
  disabled,
}) {
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);

  const pageButtons = useMemo(() => {
    const pages = Array.from({ length: pageCount }, (_, i) => i + 1);
    return pages
      .filter((p) => p === 1 || p === pageCount || Math.abs(p - page) <= 1)
      .reduce((acc, p, i, arr) => {
        if (i > 0 && p - arr[i - 1] > 1) acc.push('…');
        acc.push(p);
        return acc;
      }, []);
  }, [page, pageCount]);

  return (
    <div className="flex flex-col-reverse sm:flex-row sm:items-center sm:justify-between gap-ds-3 text-ds-caption text-text-muted">
      <p className="tabular-nums" aria-live="polite">
        Showing <span className="text-text-secondary font-medium">{from}</span>
        {' – '}
        <span className="text-text-secondary font-medium">{to}</span>
        {' of '}
        <span className="text-text-secondary font-medium">{total}</span>
      </p>
      <nav className="flex items-center gap-ds-1 flex-wrap" aria-label="Pagination">
        <IconButton label="Previous page" onClick={onPrev} disabled={disabled || page <= 1}>
          <ChevronLeftIcon className="w-4 h-4" />
        </IconButton>
        {pageButtons.map((p, i) =>
          p === '…' ? (
            <span key={`e-${i}`} className="px-ds-2 text-text-muted">
              …
            </span>
          ) : (
            <button
              key={p}
              type="button"
              onClick={() => onPage(p)}
              disabled={disabled}
              aria-label={`Page ${p}`}
              aria-current={p === page ? 'page' : undefined}
              className={`min-w-ds-8 h-ds-8 px-ds-2 rounded-ds-md text-ds-caption font-medium transition-colors ${
                p === page
                  ? 'bg-brand-primary text-white'
                  : 'hover:bg-bg-secondary text-text-secondary'
              }`}
            >
              {p}
            </button>
          )
        )}
        <IconButton label="Next page" onClick={onNext} disabled={disabled || page >= pageCount}>
          <ChevronRightIcon className="w-4 h-4" />
        </IconButton>
      </nav>
    </div>
  );
});

/**
 * Production-ready data table: search, sort, filters, pagination, responsive layout.
 *
 * @param {object} props
 * @param {object[]} props.columns
 * @param {object[]} props.data
 * @param {boolean} [props.loading]
 * @param {boolean} [props.searchable]
 * @param {string} [props.searchPlaceholder]
 * @param {string} [props.emptyMessage]
 * @param {string} [props.caption]
 * @param {number} [props.defaultPageSize]
 * @param {number[]} [props.pageSizeOptions]
 * @param {object[]} [props.filterConfig] — see useFilters / filterRowsByConfig
 */
function DataTable({
  columns = [],
  data = [],
  pageSize: initialPageSizeProp,
  searchable = true,
  emptyMessage = 'No data found',
  loading = false,
  caption,
  defaultPageSize = 10,
  pageSizeOptions = [10, 15, 20, 50],
  filterConfig = [],
  searchPlaceholder = 'Search…',
  searchKeys,
}) {
  const initialPageSize = initialPageSizeProp ?? defaultPageSize;

  const table = useTable({
    data,
    columns,
    filterConfig,
    defaultPageSize: initialPageSize,
    searchKeys,
  });

  const {
    search,
    onSearchChange,
    sortKey,
    sortDir,
    onSort,
    page,
    setPage,
    pageSize,
    onPageSizeChange,
    pageCount,
    total,
    paginated,
    filterValues,
    setFilter,
    resetFilters,
    goPrev,
    goNext,
    goToPage,
  } = table;

  const hasActiveFilters = useMemo(
    () =>
      filterConfig.some((c) => {
        const v = filterValues[c.id];
        return v !== undefined && v !== null && v !== '';
      }),
    [filterConfig, filterValues]
  );

  const handleResetFilters = useCallback(() => {
    resetFilters();
    setPage(1);
  }, [resetFilters, setPage]);

  const skeletonRows = useMemo(() => Array.from({ length: pageSize }), [pageSize]);

  const searchId = 'datatable-global-search';

  return (
    <div className="flex flex-col gap-ds-5 w-full min-w-0">
      <div className="flex flex-col gap-ds-4 xl:flex-row xl:items-start xl:justify-between">
        {searchable ? (
          <SearchField
            value={search}
            onChange={onSearchChange}
            placeholder={searchPlaceholder}
            id={searchId}
          />
        ) : null}
        <PageSizeSelect
          id="datatable-page-size"
          value={pageSize}
          options={pageSizeOptions}
          onChange={onPageSizeChange}
          disabled={loading}
        />
      </div>

      <FilterBar
        filterConfig={filterConfig}
        filterValues={filterValues}
        onFilterChange={setFilter}
        onReset={handleResetFilters}
        showReset={hasActiveFilters && filterConfig.length > 0}
      />

      <div role="status" className="sr-only" aria-live="polite">
        {!loading && `${total} result${total !== 1 ? 's' : ''} after filters`}
      </div>

      <div className="overflow-x-auto rounded-ds-xl border border-border-dim -mx-px">
        <table
          className="w-full min-w-[640px] text-ds-caption sm:text-ds-body-sm"
          role="table"
          aria-rowcount={loading ? undefined : total}
        >
          {caption ? <caption className="sr-only">{caption}</caption> : null}
          <thead>
            <tr className="border-b border-border-dim bg-bg-secondary/50">
              {columns.map((col) => {
                const isSortable = col.sortable !== false;
                const sorted = sortKey === col.key;
                const ariaSort = !isSortable
                  ? undefined
                  : sorted
                    ? sortDir === 'asc'
                      ? 'ascending'
                      : 'descending'
                    : 'none';

                return (
                  <th
                    key={col.key}
                    scope="col"
                    aria-sort={ariaSort}
                    className={`px-ds-4 py-ds-3 text-left text-ds-micro sm:text-xs font-semibold text-text-muted uppercase tracking-ds-wider whitespace-nowrap ${col.className || ''}`}
                  >
                    {isSortable ? (
                      <button
                        type="button"
                        onClick={() => onSort(col.key)}
                        className="flex items-center gap-ds-1 hover:text-text-primary transition-colors text-left w-full"
                        aria-label={`Sort by ${col.label}${sorted ? `, ${sortDir === 'asc' ? 'ascending' : 'descending'}` : ''}`}
                      >
                        <span>{col.label}</span>
                        <span className="flex flex-col -space-y-1 shrink-0" aria-hidden>
                          <ChevronUpIcon
                            className={`w-3 h-3 ${sorted && sortDir === 'asc' ? 'text-brand-primary' : 'opacity-30'}`}
                          />
                          <ChevronDownIcon
                            className={`w-3 h-3 ${sorted && sortDir === 'desc' ? 'text-brand-primary' : 'opacity-30'}`}
                          />
                        </span>
                      </button>
                    ) : (
                      col.label
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              skeletonRows.map((_, i) => (
                <tr key={i} className="border-b border-border-dim/50">
                  {columns.map((col) => (
                    <td key={col.key} className="px-ds-4 py-ds-3">
                      <div
                        className="h-4 bg-bg-secondary rounded animate-pulse"
                        style={{ width: `${60 + ((i + col.key.length) % 30)}%` }}
                      />
                    </td>
                  ))}
                </tr>
              ))
            ) : paginated.length === 0 ? (
              <tr>
                <td colSpan={columns.length}>
                  <div className="flex flex-col items-center justify-center py-ds-16 text-text-muted gap-ds-3">
                    <svg
                      className="w-12 h-12 opacity-30"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      aria-hidden
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={1.5}
                        d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 012-2h2a2 2 0 012 2M9 5h6"
                      />
                    </svg>
                    <p className="text-ds-body-sm">{emptyMessage}</p>
                  </div>
                </td>
              </tr>
            ) : (
              paginated.map((row, i) => (
                <tr
                  key={row.id ?? `${page}-${i}`}
                  className="border-b border-border-dim/50 hover:bg-bg-secondary/40 transition-colors"
                >
                  {columns.map((col) => (
                    <td
                      key={col.key}
                      className={`px-ds-4 py-ds-3 text-text-secondary align-middle ${col.className || ''}`}
                    >
                      {renderCell(col, row)}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {!loading && total > 0 ? (
        <PaginationFooter
          page={page}
          pageCount={pageCount}
          total={total}
          pageSize={pageSize}
          onPrev={goPrev}
          onNext={goNext}
          onPage={goToPage}
          disabled={loading}
        />
      ) : null}
    </div>
  );
}

export default memo(DataTable);
