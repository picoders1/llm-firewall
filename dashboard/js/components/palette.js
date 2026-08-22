/**
 * Command palette (Ctrl/Cmd+K) and the keyboard-shortcut sheet (?).
 *
 * ## What a command palette may contain here
 *
 * Navigation and view state only. The operator console is read-only by
 * construction — the operator surface refuses every non-GET at the middleware
 * boundary (ADR-023) — so there is no "block this caller" or "disable detector"
 * command to add, and one must never appear. Everything here either moves the
 * browser to a URL or changes a local display preference.
 *
 * That is also why the palette is genuinely useful rather than decorative: an
 * investigation on this console *is* a sequence of navigations, and typing a
 * request id to jump straight to its trace is the fastest path there is.
 *
 * Focus is trapped while open and restored on close, and the whole thing is
 * driven from the keyboard, because that is the point of it.
 */

import { el, icon, render } from "../dom.js";
import { path } from "../router.js";

const VIEWS = [
  { label: "Overview", hint: "Security posture across inspected traffic", to: "/", keys: "G then O" },
  { label: "Security Events", hint: "Every non-benign decision", to: "/events", keys: "G then E" },
  { label: "Detector & Policy", hint: "What inspects traffic, and what only watches", to: "/detectors", keys: "G then D" },
  { label: "Traffic & Latency", hint: "Throughput and where the time goes", to: "/traffic", keys: "G then T" },
  { label: "Evaluation", hint: "Measured detection quality", to: "/evaluations", keys: "G then V" },
  { label: "System Health", hint: "Process, dependencies and readiness", to: "/system", keys: "G then S" },
];

const FILTERS = [
  { label: "Blocked requests", hint: "Events where the policy blocked", to: "/events?decision=block" },
  { label: "Redacted requests", hint: "Events where content was redacted", to: "/events?decision=redact" },
  { label: "Detector failures", hint: "Events where a detector failed closed", to: "/events?decision=detector_failure" },
  { label: "Output-side events", hint: "Findings on the model's response", to: "/events?direction=output" },
  { label: "Last hour", hint: "Narrow the event window", to: "/events?hours=1" },
];

export const SHORTCUTS = [
  ["Ctrl / ⌘ + K", "Open the command palette"],
  ["G then O / E / D / T / V / S", "Go to a view"],
  ["R", "Refresh the current view"],
  ["Shift + T", "Toggle light and dark"],
  ["?", "Show this help"],
  ["Esc", "Close an overlay"],
];

/** Subsequence match, so "sece" finds "Security Events". */
function score(query, text) {
  if (!query) return 0;
  const haystack = text.toLowerCase();
  const needle = query.toLowerCase();
  if (haystack.includes(needle)) return 100 - haystack.indexOf(needle);
  let index = 0;
  for (const character of needle) {
    index = haystack.indexOf(character, index);
    if (index === -1) return -1;
    index += 1;
  }
  return 1;
}

function overlay(children, onClose) {
  const previous = document.activeElement;
  const surface = el("div", { class: "overlay__surface", role: "dialog", "aria-modal": "true" }, children);
  const root = el("div", { class: "overlay", onMousedown: (event) => {
    if (event.target === root) close();
  } }, [surface]);

  function close() {
    root.remove();
    document.removeEventListener("keydown", onKey, true);
    previous?.focus?.();
    onClose?.();
  }

  function onKey(event) {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      close();
      return;
    }
    if (event.key !== "Tab") return;
    // Focus trap: an overlay the keyboard can walk out of is not a dialog.
    const focusable = surface.querySelectorAll("input, button, [tabindex]:not([tabindex='-1'])");
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  document.addEventListener("keydown", onKey, true);
  document.body.append(root);
  return { root, surface, close };
}

/** The shortcut sheet. Pure reference, no actions. */
export function openShortcuts() {
  if (document.querySelector(".overlay")) return;
  const rows = SHORTCUTS.map(([keys, description]) =>
    el("div", { class: "shortcut" }, [
      el("kbd", { class: "kbd", text: keys }),
      el("span", { class: "shortcut__desc", text: description }),
    ]),
  );
  const { surface } = overlay([
    el("header", { class: "overlay__head" }, [
      icon("keyboard", 16),
      el("h2", { class: "overlay__title", text: "Keyboard shortcuts" }),
    ]),
    el("div", { class: "overlay__body" }, rows),
  ]);
  surface.setAttribute("aria-label", "Keyboard shortcuts");
  // `-1` rather than `0`: the region needs to receive focus so the dialog is
  // announced and Esc is heard, but it is not a tab stop, and programmatic
  // focus on it must not paint a focus ring across the whole panel.
  const body = surface.querySelector(".overlay__body");
  body?.setAttribute("tabindex", "-1");
  body?.focus();
}

/**
 * @param {{navigate: Function, onToggleTheme: Function, onRefresh: Function}} actions
 */
export function openPalette(actions) {
  if (document.querySelector(".overlay")) return;

  const commands = [
    ...VIEWS.map((view) => ({ ...view, group: "Go to", run: () => actions.navigate(path(view.to)) })),
    ...FILTERS.map((filter) => ({ ...filter, group: "Filter", run: () => actions.navigate(path(filter.to)) })),
    {
      label: "Refresh this view",
      hint: "Re-request the data behind the current screen",
      group: "Console",
      keys: "R",
      run: () => actions.onRefresh(),
    },
    {
      label: "Toggle theme",
      hint: "Switch between the light and dark scheme",
      group: "Console",
      keys: "Shift + T",
      run: () => actions.onToggleTheme(),
    },
    {
      label: "Keyboard shortcuts",
      hint: "Everything this console can do from the keyboard",
      group: "Console",
      keys: "?",
      run: () => openShortcuts(),
    },
  ];

  const list = el("div", { class: "palette__list", role: "listbox", id: "palette-list" });
  const empty = el("p", { class: "palette__empty" });
  let active = 0;
  let visible = commands;

  const input = el("input", {
    class: "palette__input",
    type: "text",
    role: "combobox",
    "aria-expanded": "true",
    "aria-controls": "palette-list",
    "aria-autocomplete": "list",
    "aria-label": "Search commands, or paste a request id",
    placeholder: "Search views and filters, or paste a request id…",
    autocomplete: "off",
    spellcheck: "false",
  });

  function commit(command) {
    close();
    command.run();
  }

  function paint() {
    const query = input.value.trim();

    // A 32-hex correlation id is unambiguous, so offer the jump directly rather
    // than making the operator find the right filter field for it.
    const idJump = /^[0-9a-f]{8,64}$/i.test(query)
      ? [{
          label: `Find request ${query}`,
          hint: "Open the event list filtered to this correlation id",
          group: "Jump",
          run: () => actions.navigate(path(`/events?request_id=${encodeURIComponent(query)}`)),
        }]
      : [];

    visible = [
      ...idJump,
      ...commands
        .map((command) => ({ command, rank: score(query, `${command.label} ${command.hint}`) }))
        .filter(({ rank }) => rank >= 0)
        .sort((a, b) => b.rank - a.rank)
        .map(({ command }) => command),
    ];

    active = 0;
    render(list);
    if (!visible.length) {
      empty.textContent = `No command matches “${query}”.`;
      render(list, empty);
      return;
    }

    let lastGroup = null;
    visible.forEach((command, index) => {
      if (command.group !== lastGroup) {
        lastGroup = command.group;
        list.append(el("div", { class: "palette__group", text: command.group }));
      }
      list.append(
        el(
          "button",
          {
            class: `palette__item${index === active ? " palette__item--active" : ""}`,
            type: "button",
            role: "option",
            "aria-selected": index === active ? "true" : "false",
            dataset: { index: String(index) },
            onClick: () => commit(command),
            onMousemove: () => setActive(index),
          },
          [
            el("span", { class: "palette__label", text: command.label }),
            el("span", { class: "palette__hint truncate", text: command.hint }),
            command.keys ? el("kbd", { class: "kbd kbd--sm", text: command.keys }) : null,
          ],
        ),
      );
    });
  }

  function setActive(index) {
    const items = list.querySelectorAll(".palette__item");
    if (!items.length) return;
    active = (index + items.length) % items.length;
    items.forEach((item, position) => {
      const isActive = position === active;
      item.classList.toggle("palette__item--active", isActive);
      item.setAttribute("aria-selected", isActive ? "true" : "false");
      if (isActive) item.scrollIntoView({ block: "nearest" });
    });
  }

  input.addEventListener("input", paint);
  input.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive(active + 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive(active - 1);
    } else if (event.key === "Enter") {
      event.preventDefault();
      if (visible[active]) commit(visible[active]);
    }
  });

  const { surface, close } = overlay([
    el("div", { class: "palette__search" }, [icon("search", 16), input]),
    list,
    el("footer", { class: "palette__foot" }, [
      el("span", {}, [el("kbd", { class: "kbd kbd--sm", text: "↑↓" }), " to move"]),
      el("span", {}, [el("kbd", { class: "kbd kbd--sm", text: "↵" }), " to open"]),
      el("span", {}, [el("kbd", { class: "kbd kbd--sm", text: "Esc" }), " to dismiss"]),
      el("span", { class: "palette__readonly", text: "Read-only console" }),
    ]),
  ]);
  surface.classList.add("overlay__surface--palette");
  surface.setAttribute("aria-label", "Command palette");
  paint();
  input.focus();
}
