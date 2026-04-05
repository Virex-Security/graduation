import { memo, useId } from 'react';
import { InformationCircleIcon } from '@heroicons/react/24/outline';

/**
 * Accessible toggle. Optional `tooltip` shows hover/focus hint next to the label.
 */
function InfoTooltip({ text }) {
  const tipId = useId();
  if (!text) return null;

  return (
    <span className="group/tooltip relative inline-flex shrink-0 align-middle">
      <span
        tabIndex={0}
        className="cursor-help rounded-full p-0.5 text-text-muted outline-none hover:text-brand-primary focus-visible:text-brand-primary focus-visible:ring-2 focus-visible:ring-brand-primary focus-visible:ring-offset-2 focus-visible:ring-offset-bg-main"
        aria-describedby={tipId}
      >
        <InformationCircleIcon className="h-4 w-4" aria-hidden />
      </span>
      <span
        id={tipId}
        role="tooltip"
        className="pointer-events-none absolute bottom-full left-1/2 z-30 mb-ds-2 w-56 -translate-x-1/2 rounded-ds-md border border-border-dim bg-bg-secondary/95 px-ds-3 py-ds-2 text-left text-ds-caption leading-snug text-text-secondary opacity-0 shadow-ds-card backdrop-blur-md transition-opacity duration-200 group-hover/tooltip:opacity-100 group-focus-within/tooltip:opacity-100"
      >
        {text}
      </span>
    </span>
  );
}

function ToggleSwitch({
  id,
  label,
  description,
  checked,
  onChange,
  tooltip,
  disabled = false,
}) {
  const autoId = useId();
  const switchId = id ?? autoId;

  return (
    <div className="flex flex-col gap-ds-1 py-ds-4 sm:flex-row sm:items-center sm:justify-between sm:gap-ds-6">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-ds-2">
          <span className="text-ds-body-sm font-medium text-text-primary" id={`${switchId}-label`}>
            {label}
          </span>
          <InfoTooltip text={tooltip} />
        </div>
        {description ? (
          <p className="mt-ds-1 text-ds-caption text-text-muted">{description}</p>
        ) : null}
      </div>
      <button
        id={switchId}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-labelledby={`${switchId}-label`}
        disabled={disabled}
        title={tooltip || undefined}
        onClick={() => !disabled && onChange(!checked)}
        className={`relative inline-flex h-7 w-12 shrink-0 items-center rounded-full transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-primary focus-visible:ring-offset-2 focus-visible:ring-offset-bg-main motion-reduce:transition-none ${
          disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'
        } ${checked ? 'bg-brand-primary' : 'border border-border-light bg-bg-secondary'}`}
      >
        <span
          className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-md transition-transform duration-200 motion-reduce:transition-none ${
            checked ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
    </div>
  );
}

export default memo(ToggleSwitch);
export { InfoTooltip };
