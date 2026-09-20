/**
 * Parse a timestamp coming from the OTShield backend and return epoch millis.
 *
 * The backend serialises naive UTC timestamps (e.g. "2026-09-20T21:35:43.831")
 * with no 'Z' or offset. `new Date(...)` then parses them as the viewer's LOCAL
 * time, which skews every relative-time ("X ago") and time-window calculation by
 * the browser's UTC offset — e.g. a 32-minute-old event renders "1h ago" at
 * UTC+1. Appending 'Z' when no timezone marker is present forces UTC parsing.
 *
 * Strings that already carry a 'Z' or a ±HH:MM offset are left untouched, so
 * client-generated ISO strings (Date.toISOString()) keep working.
 */
export const parseServerTime = (iso: string | null | undefined): number => {
  if (!iso) return NaN;
  const utc = /([zZ]|[+-]\d{2}:?\d{2})$/.test(iso) ? iso : iso + 'Z';
  return new Date(utc).getTime();
};
