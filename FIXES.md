# Rate Limit UI Fixes

Tracking file for rate-limit advisor panel clarity, readability, and correctness fixes.
Branch: `fix/rate-limit-ui-clarity`

## Visual / Readability Issues (from screenshot)

- [x] **F1 — Time-of-Day bottom stats unreadable**: Removed the per-hour stats strip below the chart. The dense `0.000/0.009 rps (7c, str)...` text was illegible at any screen size.
- [x] **F2 — Impact Curve X-axis dominated by outliers**: Added sqrt-scale X-axis when the threshold range exceeds 10x. Compresses the long tail while expanding the dense low-value region where threshold decisions actually matter.
- [x] **F3 — Distribution Histogram sparse right tail**: Replaced equal-width bars with sqrt-scaled positioning. Dense low-value bins (where most clients cluster) now get proportionally more horizontal space. Tail bins with 1-2 clients at 566/2320/3712 are compressed but still visible (minimum 6px width).
- [x] **F4 — Time-of-Day chart dead space**: Added minimum bar height of 3px for non-zero values. Hours with 0.001 rps are now visible even when one hour spikes at 1.3 rps.

## Functional / Correctness Issues

- [x] **F5 — Dialog closes before async completes**: Moved `closeDialog()` inside the success path of `handleCreate`/`handleUpdate`. On API error, the dialog stays open and the user's form data is preserved.
- [x] **F6 — No loading/disabled state during CRUD**: Added `saving` state. Submit/cancel/delete buttons show spinner and are disabled during async operations. Prevents double-submit.
- [x] **F7 — Stale error not cleared before new operations**: All CRUD handlers now call `setError(null)` before starting.
- [x] **F8 — Pagination renders when filteredRules is empty**: `TablePagination` is now conditionally rendered only when `filteredRules.length > 0`.

## Code Quality

- [x] **F9 — Duplicated `isValidWindow`**: Extracted to `src/lib/format.ts`. Both panels now import from the shared location.
- [x] **F10 — SVG clipPath IDs not unique**: Replaced hardcoded `id="impact-clip"` and `id="tod-clip"` with React `useId()` for guaranteed uniqueness.
- [x] **F11 — Advisor `onCreateRule` not memoized**: Extracted to a `useCallback`-wrapped `handleAdvisorCreateRule` handler.

## Verification

- 265/265 frontend tests pass (Vitest)
- Astro build succeeds (8 pages, 4.6s)
- No new TypeScript errors introduced
