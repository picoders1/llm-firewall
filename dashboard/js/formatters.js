/**
 * Presentation formatting.
 *
 * One rule governs this module: **a missing value must never render as a
 * number.** The backend returns `null` for a percentile with no observations,
 * and showing `0 ms` there would report the fastest possible system where in
 * fact nothing was measured. Every formatter here returns a marker string for
 * null/undefined rather than coercing.
 *
 * The second rule is not to round away evidence. An FPR of 0.0092 is not "1%";
 * `formatRate` keeps enough precision that a small rate stays legible as one.
 */

export const NOT_AVAILABLE = "Not available";
export const NO_OBSERVATIONS = "No observations";

const isMissing = (value) => value === null || value === undefined || Number.isNaN(value);

export function formatCount(value) {
  if (isMissing(value)) return NOT_AVAILABLE;
  return new Intl.NumberFormat("en", { maximumFractionDigits: 0 }).format(value);
}

/** Latency. Sub-millisecond values keep two decimals; a 0.5 ms gateway hop is
 *  real and rounding it to "1 ms" would double it. */
export function formatDuration(ms) {
  if (isMissing(ms)) return NO_OBSERVATIONS;
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 100) return `${ms.toFixed(1)} ms`;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

/**
 * A rate in [0,1] as a percentage, keeping small rates readable.
 * 0.0092 -> "0.92%", not "1%".
 */
export function formatRate(value) {
  if (isMissing(value)) return NOT_AVAILABLE;
  const pct = value * 100;
  if (pct === 0) return "0%";
  if (pct < 0.01) return `${pct.toExponential(1)}%`;
  if (pct < 1) return `${pct.toFixed(2)}%`;
  if (pct < 10) return `${pct.toFixed(2)}%`;
  return `${pct.toFixed(1)}%`;
}

/** A model score or metric in [0,1]. Four decimals: thresholds like 0.9955 and
 *  0.9954 differ in the fourth place, and collapsing them hides the difference. */
export function formatScore(value) {
  if (isMissing(value)) return NOT_AVAILABLE;
  return Number(value).toFixed(4);
}

export function formatTimestamp(value, { seconds = true } = {}) {
  if (!value) return NOT_AVAILABLE;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return NOT_AVAILABLE;
  return new Intl.DateTimeFormat("en-GB", {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
    ...(seconds ? { second: "2-digit" } : {}),
    hour12: false,
  }).format(date);
}

export function formatTime(value) {
  if (!value) return NOT_AVAILABLE;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return NOT_AVAILABLE;
  return new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false }).format(date);
}

export function formatRelative(value) {
  if (!value) return NOT_AVAILABLE;
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return NOT_AVAILABLE;
  const seconds = Math.round((then - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  if (abs < 60) return rtf.format(Math.round(seconds), "second");
  if (abs < 3600) return rtf.format(Math.round(seconds / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(seconds / 3600), "hour");
  return rtf.format(Math.round(seconds / 86400), "day");
}

export function formatUptime(totalSeconds) {
  if (isMissing(totalSeconds)) return NOT_AVAILABLE;
  const s = Math.floor(totalSeconds);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${s % 60}s`;
  return `${s}s`;
}

/** A confidence interval as text. Absent bounds are stated, never invented. */
export function formatInterval(pair) {
  if (!Array.isArray(pair) || pair.length !== 2) return null;
  const [low, high] = pair;
  if (isMissing(low) || isMissing(high)) return null;
  return `${Number(low).toFixed(4)} – ${Number(high).toFixed(4)}`;
}

export function titleCase(value) {
  if (!value) return "";
  return String(value)
    .replace(/[_.]/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

/** Percentage of a total, for distribution bars. Guards divide-by-zero. */
export function share(part, total) {
  if (!total || isMissing(part)) return 0;
  return (part / total) * 100;
}
