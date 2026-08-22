/**
 * `el()` must apply styles through the CSSOM, never as an attribute.
 *
 * The console is served under `style-src 'self'` with no `'unsafe-inline'`, so a
 * style **attribute** is refused by the browser. When `el()` accepted style
 * strings and passed them to `setAttribute`, every one was silently dropped:
 * distribution bars rendered 0px wide and bar-list labels ran into their values.
 *
 * `tests/security/test_dashboard_frontend_safety.py` asserts no call site writes
 * a style string. This asserts the other half — that the mechanism they all rely
 * on does the right thing.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

/** The smallest element `el()` actually uses. */
function fakeElement(tag) {
  const properties = new Map();
  return {
    tagName: tag.toUpperCase(),
    attributes: new Map(),
    children: [],
    textContent: "",
    className: "",
    dataset: {},
    style: {
      setProperty(name, value) {
        properties.set(name, value);
      },
      _properties: properties,
    },
    setAttribute(name, value) {
      this.attributes.set(name, value);
    },
    addEventListener() {},
    append(...nodes) {
      this.children.push(...nodes);
    },
  };
}

globalThis.document = {
  createElement: fakeElement,
  createElementNS: (_ns, tag) => fakeElement(tag),
  createTextNode: (text) => ({ text }),
};

const { el, svg } = await import("../../dashboard/js/dom.js");

test("a style object is applied through the CSSOM, not as an attribute", () => {
  const node = el("div", { style: { "--bar-width": "42%", color: "red" } });
  assert.equal(node.style._properties.get("--bar-width"), "42%");
  assert.equal(node.style._properties.get("color"), "red");
  assert.equal(node.attributes.has("style"), false, "style must never become an attribute");
});

test("a style string is refused rather than silently dropped by the browser", () => {
  assert.throws(() => el("div", { style: "width:42%" }), /Content Security Policy|object/);
});

test("SVG nodes take the same path", () => {
  const node = svg("rect", { style: { fill: "blue" }, width: 10 });
  assert.equal(node.style._properties.get("fill"), "blue");
  assert.equal(node.attributes.get("width"), "10");
  assert.equal(node.attributes.has("style"), false);
});

test("null and undefined style values are skipped, not stringified", () => {
  const node = el("div", { style: { color: null, background: undefined, width: "1px" } });
  assert.equal(node.style._properties.has("color"), false);
  assert.equal(node.style._properties.has("background"), false);
  assert.equal(node.style._properties.get("width"), "1px");
});
