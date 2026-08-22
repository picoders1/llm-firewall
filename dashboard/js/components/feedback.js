/**
 * Transient feedback: toasts, and copy-to-clipboard.
 *
 * ## Why copying needs a fallback
 *
 * `navigator.clipboard` exists only in a **secure context**. The console is
 * routinely opened over plain HTTP on a LAN address, which is not one —
 * `navigator.clipboard` is `undefined` there, and a copy button that works on
 * localhost and silently does nothing on the host an operator actually uses is
 * worse than no button.
 *
 * So there are three tiers, and the last one always works:
 *   1. the async Clipboard API, when the page is in a secure context;
 *   2. `document.execCommand("copy")`, deprecated but universally implemented;
 *   3. selecting the text, so the operator can copy it by hand.
 *
 * The toast reports which of those happened. It never claims success it did not
 * achieve.
 */

import { el, icon } from "../dom.js";

const TOAST_MS = 2600;
let host = null;

function toastHost() {
  if (!host) {
    host = el("div", { class: "toasts", role: "status", "aria-live": "polite" });
    document.body.append(host);
  }
  return host;
}

/** @param {"ok"|"error"|"info"} kind */
export function toast(message, kind = "ok") {
  const node = el("div", { class: `toast toast--${kind}` }, [
    icon(kind === "error" ? "alert" : kind === "info" ? "info" : "check", 14),
    el("span", { text: message }),
  ]);
  toastHost().append(node);
  const remove = () => node.remove();
  node.addEventListener("animationend", (event) => {
    if (event.animationName === "toast-out") remove();
  });
  setTimeout(() => node.classList.add("toast--leaving"), TOAST_MS);
  // A toast must not outlive its animation even if the animation never runs
  // (reduced motion, background tab).
  setTimeout(remove, TOAST_MS + 1200);
  return node;
}

/** Copy text, degrading through the tiers above. Returns the tier that worked. */
export async function copyText(text, { node = null } = {}) {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      toast("Copied to clipboard");
      return "clipboard";
    } catch {
      /* fall through: a permission refusal is not a reason to give up */
    }
  }

  const scratch = el("textarea", { class: "sr-only", "aria-hidden": "true" });
  scratch.value = text;
  document.body.append(scratch);
  scratch.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch {
    copied = false;
  }
  scratch.remove();

  if (copied) {
    toast("Copied to clipboard");
    return "execCommand";
  }

  // Last resort: put the value under the operator's cursor and say so plainly.
  if (node) {
    const range = document.createRange();
    range.selectNodeContents(node);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }
  toast("Selected — press Ctrl+C to copy", "info");
  return "selection";
}

/**
 * A value with a copy affordance beside it.
 * Read-only: copying moves nothing on the server (ADR-023).
 */
export function copyable(text, { mono = true, label = "value" } = {}) {
  const value = el("span", { class: mono ? "mono truncate" : "truncate", text, title: text });
  const button = el(
    "button",
    {
      class: "copy",
      type: "button",
      "aria-label": `Copy ${label}`,
      title: `Copy ${label}`,
      onClick: (event) => {
        event.stopPropagation();
        copyText(text, { node: value });
      },
    },
    [icon("copy", 13)],
  );
  return el("span", { class: "copyfield" }, [value, button]);
}
