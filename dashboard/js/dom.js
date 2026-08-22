/**
 * Safe DOM construction.
 *
 * This application never assigns `innerHTML`. Not for server data, not for
 * "trusted" data, not for icons. The rule is absolute because the exceptions are
 * where the bugs live: a security-event `category` is server-controlled, and one
 * `innerHTML` on a detail panel would turn a detector label into an execution
 * primitive.
 *
 * Everything below builds nodes with `createElement` and assigns text through
 * `textContent`, which cannot produce markup. Attributes are set through
 * `setAttribute`, with `href` validated separately (`safeHref`).
 *
 * ## Styles are objects, never strings
 *
 * The dashboard is served under `style-src 'self'` with no `'unsafe-inline'`
 * (app/api/dashboard_static.py). That directive refuses **style attributes**,
 * and `setAttribute("style", ...)` is exactly that — the browser drops it and
 * logs a CSP violation. It does NOT refuse CSSOM assignment, because the script
 * doing the assigning already passed `script-src`.
 *
 * So `style` takes an object and is applied property-by-property through
 * `node.style.setProperty`. Passing a string throws rather than silently
 * producing an element the browser will render unstyled — which is how a
 * distribution bar ends up 0px wide and a label ends up glued to its value.
 */

const SVG_NS = "http://www.w3.org/2000/svg";

/**
 * Create an element.
 * @param {string} tag
 * @param {object} [attrs] - `class`, `text`, `dataset`, `on*` handlers, or any attribute.
 * @param {Array<Node|string|null|undefined>} [children]
 */
export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  applyAttrs(node, attrs);
  appendAll(node, children);
  return node;
}

/** Create an SVG element. Icons are built as nodes, never parsed from strings. */
export function svg(tag, attrs = {}, children = []) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "style") {
      applyStyle(node, value);
      continue;
    }
    node.setAttribute(key, String(value));
  }
  appendAll(node, children);
  return node;
}

function applyAttrs(node, attrs) {
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "text") {
      // textContent, never innerHTML: markup in server data stays inert text.
      node.textContent = String(value);
    } else if (key === "class") {
      node.className = String(value);
    } else if (key === "dataset") {
      for (const [dataKey, dataValue] of Object.entries(value)) {
        if (dataValue !== null && dataValue !== undefined) node.dataset[dataKey] = String(dataValue);
      }
    } else if (key.startsWith("on") && typeof value === "function") {
      // Listener objects, not attribute strings: nothing server-provided can
      // ever reach an inline event-handler attribute.
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === "style") {
      applyStyle(node, value);
    } else if (key === "href") {
      const safe = safeHref(value);
      if (safe !== null) node.setAttribute("href", safe);
    } else {
      node.setAttribute(key, String(value));
    }
  }
}

/**
 * Apply styles through the CSSOM, which CSP permits, rather than through a
 * style attribute, which it does not.
 *
 * Dynamic geometry is passed as a custom property (`{"--fill": "42%"}`) and
 * consumed by a stylesheet rule, so the *shape* of a component stays in CSS and
 * only the measurement comes from JavaScript.
 */
function applyStyle(node, value) {
  if (typeof value === "string") {
    throw new TypeError(
      "style must be an object: a style string is applied as an attribute, which the dashboard's Content Security Policy refuses",
    );
  }
  for (const [property, raw] of Object.entries(value)) {
    if (raw === null || raw === undefined || raw === false) continue;
    node.style.setProperty(property, String(raw));
  }
}

function appendAll(node, children) {
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

/**
 * Allow only same-origin paths and fragments.
 *
 * Rejects `javascript:`, `data:`, protocol-relative `//evil` and absolute
 * external URLs. Returns null when the value cannot be trusted, and the caller
 * then omits the attribute rather than emitting a broken one.
 */
export function safeHref(value) {
  const raw = String(value ?? "").trim();
  if (raw.startsWith("#")) return raw;
  if (!raw.startsWith("/") || raw.startsWith("//")) return null;
  return raw;
}

/** Replace a container's children. */
export function render(container, ...children) {
  container.replaceChildren();
  appendAll(container, children);
  return container;
}

export function fragment(children) {
  const frag = document.createDocumentFragment();
  appendAll(frag, children);
  return frag;
}

/** Icon paths. Static constants defined here, never sourced from the server. */
const ICONS = {
  overview: "M3 3h7v7H3zM14 3h7v4h-7zM14 10h7v11h-7zM3 13h7v8H3z",
  events: "M4 4h16v4H4zM4 11h16v3H4zM4 17h10v3H4z",
  detectors: "M12 2 4 5.5v6c0 5 3.4 9.7 8 10.5 4.6-.8 8-5.5 8-10.5v-6L12 2z",
  traffic: "M3 17l5-6 4 4 5-7 4 5",
  evaluations: "M4 20V9m5 11V4m5 16v-8m5 8V7",
  system: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 7v6l4 2",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6",
  menu: "M4 6h16M4 12h16M4 18h16",
  close: "M6 6l12 12M18 6L6 18",
  chevron: "M9 6l6 6-6 6",
  back: "M15 6l-6 6 6 6",
  alert: "M12 3 2 20h20L12 3zM12 9v5M12 17v.5",
  empty: "M4 7h16v13H4zM4 7l2-3h12l2 3M9 12h6",
  info: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 11v6M12 7v.5",
  check: "M4 12l5 5L20 6",
  sun: "M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon: "M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z",
  copy: "M9 9h10v10H9zM5 15H4V4h11v1",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4",
  sort: "M8 9l4-4 4 4M8 15l4 4 4-4",
  "sort-asc": "M8 14l4-4 4 4",
  "sort-desc": "M8 10l4 4 4-4",
  keyboard: "M3 6h18v12H3zM7 10h.01M11 10h.01M15 10h.01M8 14h8",
  filter: "M3 5h18l-7 8v5l-4 2v-7z",
  pulse: "M3 12h4l2-6 4 12 2-6h6",
  lock: "M6 11h12v9H6zM9 11V7a3 3 0 0 1 6 0v4",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
};

/** @param {keyof ICONS} name */
export function icon(name, size = 16) {
  return svg(
    "svg",
    {
      width: size,
      height: size,
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      "stroke-width": 1.7,
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      "aria-hidden": "true",
      focusable: "false",
    },
    [svg("path", { d: ICONS[name] ?? ICONS.info })],
  );
}
