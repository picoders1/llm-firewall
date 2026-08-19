/**
 * Safe-rendering guarantees.
 *
 * `safeHref` is the one place a server-derived string could become a navigation
 * target, so it is tested against the payloads that matter rather than a happy
 * path.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { safeHref } from "../../dashboard/js/dom.js";

test("javascript: URLs are refused", () => {
  assert.equal(safeHref("javascript:alert(1)"), null);
  assert.equal(safeHref("JaVaScRiPt:alert(1)"), null);
  assert.equal(safeHref("  javascript:alert(1)  "), null);
});

test("data: and external URLs are refused", () => {
  assert.equal(safeHref("data:text/html,<script>alert(1)</script>"), null);
  assert.equal(safeHref("https://evil.example/steal"), null);
  assert.equal(safeHref("//evil.example/steal"), null);
});

test("same-origin paths and fragments are allowed", () => {
  assert.equal(safeHref("/dashboard/events"), "/dashboard/events");
  assert.equal(safeHref("#main"), "#main");
});

test("an empty or missing href yields null rather than an empty attribute", () => {
  assert.equal(safeHref(""), null);
  assert.equal(safeHref(null), null);
  assert.equal(safeHref(undefined), null);
});
