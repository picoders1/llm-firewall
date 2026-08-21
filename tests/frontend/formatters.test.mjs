/**
 * Formatter behaviour, run with node's built-in test runner.
 *
 * Chosen over Playwright deliberately: these are pure functions, and the rules
 * they encode are the ones most likely to produce a *wrong number on screen* —
 * which is the failure mode this project cares about most. A browser driver
 * would test that they were called, not that they are right.
 *
 *   node --test tests/frontend/*.test.mjs
 *
 * The directory form (`node --test tests/frontend/`) is NOT equivalent on Node 22:
 * it resolves the directory as a module and exits 1 before running anything, which
 * looks exactly like a failing suite. Corrected in Phase 19 after CI was found not
 * to run these at all.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  NOT_AVAILABLE,
  NO_OBSERVATIONS,
  formatCount,
  formatDuration,
  formatInterval,
  formatRate,
  formatScore,
  formatUptime,
  share,
} from "../../dashboard/js/formatters.js";

test("a missing latency is never rendered as a number", () => {
  // The whole point: 0 ms is the fastest possible system; null is no system.
  assert.equal(formatDuration(null), NO_OBSERVATIONS);
  assert.equal(formatDuration(undefined), NO_OBSERVATIONS);
  assert.equal(formatDuration(NaN), NO_OBSERVATIONS);
  assert.notEqual(formatDuration(null), "0 ms");
});

test("a measured zero is still shown as a measurement", () => {
  assert.equal(formatDuration(0), "0.00 ms");
});

test("sub-millisecond latency keeps precision", () => {
  // The live gateway measures ~0.5 ms; rounding to "1 ms" would double it.
  assert.equal(formatDuration(0.501), "0.50 ms");
  assert.equal(formatDuration(95.38), "95.4 ms");
  assert.equal(formatDuration(1650), "1.65 s");
});

test("a small false-positive rate is not rounded into a bigger one", () => {
  // 0.0092 is the project's published benign FPR. "1%" would overstate it.
  assert.equal(formatRate(0.0092), "0.92%");
  assert.notEqual(formatRate(0.0092), "1%");
  assert.equal(formatRate(0), "0%");
  assert.equal(formatRate(null), NOT_AVAILABLE);
});

test("scores keep four decimals so adjacent thresholds stay distinguishable", () => {
  // 0.9955 and 0.9954 are two different locked thresholds in this project.
  assert.equal(formatScore(0.9955), "0.9955");
  assert.equal(formatScore(0.9954), "0.9954");
  assert.notEqual(formatScore(0.9955), formatScore(0.9954));
});

test("missing counts are stated, not zeroed", () => {
  assert.equal(formatCount(null), NOT_AVAILABLE);
  assert.equal(formatCount(0), "0");
  assert.equal(formatCount(1234), "1,234");
});

test("a confidence interval renders both bounds or nothing", () => {
  assert.equal(formatInterval([0.7989, 0.8814]), "0.7989 – 0.8814");
  assert.equal(formatInterval([null, 0.5]), null);
  assert.equal(formatInterval(null), null);
  assert.equal(formatInterval([0.1]), null);
});

test("share guards divide-by-zero rather than producing NaN", () => {
  assert.equal(share(5, 0), 0);
  assert.equal(share(null, 10), 0);
  assert.equal(share(25, 100), 25);
});

test("uptime is human readable at every scale", () => {
  assert.equal(formatUptime(null), NOT_AVAILABLE);
  assert.equal(formatUptime(45), "45s");
  assert.equal(formatUptime(3700), "1h 1m");
  assert.equal(formatUptime(90000), "1d 1h");
});
