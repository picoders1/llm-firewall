/**
 * API client.
 *
 * One place that knows how to talk to the gateway, so no page duplicates fetch
 * handling and every failure is classified the same way.
 *
 * Same-origin by construction: paths are relative, so there is no base URL to
 * configure, no CORS preflight and no credential to store. This client holds no
 * secrets and writes nothing to localStorage or sessionStorage — a security
 * console that persists a token is a console that leaks one.
 *
 * It contains **no security logic**. It does not decide, score, threshold or
 * interpret; it moves JSON and classifies transport failures.
 */

export const API_ROOT = "/api/v1";
const DEFAULT_TIMEOUT_MS = 12000;

/**
 * Failure kinds a page may branch on, so error handling never parses strings.
 *
 * UNAUTHENTICATED and FORBIDDEN are separate from CLIENT because the console has
 * to tell three situations apart and they look identical if you only have
 * "something went wrong": the session expired (reload and the boundary will sign
 * you in again), this account is not permitted (reloading will never help), and
 * the gateway is unreachable (nothing to do with identity at all).
 */
export const ErrorKind = {
  TIMEOUT: "timeout",
  NETWORK: "network",
  UNAUTHENTICATED: "unauthenticated",
  FORBIDDEN: "forbidden",
  CLIENT: "client",
  SERVER: "server",
  MALFORMED: "malformed",
};

export class ApiError extends Error {
  constructor(kind, message, { status = null, requestId = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.requestId = requestId;
  }

  /** Safe for display: never contains a response body or a stack. */
  get userMessage() {
    switch (this.kind) {
      case ErrorKind.TIMEOUT:
        return "The request timed out.";
      case ErrorKind.NETWORK:
        return "Could not reach the gateway.";
      case ErrorKind.UNAUTHENTICATED:
        return "Your operator session is no longer valid.";
      case ErrorKind.FORBIDDEN:
        return "This account is not authorised for the security console.";
      case ErrorKind.MALFORMED:
        return "The gateway returned a response this console could not read.";
      case ErrorKind.CLIENT:
        return this.message || "The request was rejected.";
      default:
        return "The gateway reported an internal error.";
    }
  }
}

/**
 * GET JSON.
 * @param {string} path - relative to the API root, or absolute same-origin.
 * @param {{params?: object, signal?: AbortSignal, timeout?: number}} [options]
 */
export async function get(path, { params = {}, signal, timeout = DEFAULT_TIMEOUT_MS } = {}) {
  const url = new URL(path.startsWith("/") ? path : `${API_ROOT}/${path}`, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === "") continue;
    url.searchParams.set(key, String(value));
  }

  // Two independent reasons to abort: the caller navigating away, and the clock.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException("timeout", "TimeoutError")), timeout);
  const onAbort = () => controller.abort(signal?.reason);
  signal?.addEventListener("abort", onAbort, { once: true });

  let response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: controller.signal,
      credentials: "same-origin",
    });
  } catch (cause) {
    if (signal?.aborted) throw cause;
    if (cause?.name === "TimeoutError" || controller.signal.reason?.name === "TimeoutError") {
      throw new ApiError(ErrorKind.TIMEOUT, "timed out");
    }
    throw new ApiError(ErrorKind.NETWORK, "network failure");
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }

  const requestId = response.headers.get("x-request-id");

  if (!response.ok) {
    // The gateway's error envelope carries a safe message; anything else is
    // ignored rather than displayed, so a raw body can never reach the DOM.
    let message = "";
    try {
      const body = await response.json();
      const candidate = body?.error?.message;
      if (typeof candidate === "string" && candidate.length < 300) message = candidate;
    } catch {
      /* body is not the envelope; the status alone classifies it */
    }
    // The server's message for 401/403 is a fixed string by design and says
    // nothing the console can act on, so the kind carries the meaning instead.
    let kind = ErrorKind.CLIENT;
    if (response.status === 401) kind = ErrorKind.UNAUTHENTICATED;
    else if (response.status === 403) kind = ErrorKind.FORBIDDEN;
    else if (response.status >= 500) kind = ErrorKind.SERVER;
    throw new ApiError(kind, message, { status: response.status, requestId });
  }

  try {
    return await response.json();
  } catch {
    throw new ApiError(ErrorKind.MALFORMED, "invalid JSON", { status: response.status, requestId });
  }
}

/**
 * Resolve several requests without letting one failure blank the page (§38).
 * Returns `{ key: {ok, data|error} }` so a caller renders what succeeded.
 */
export async function getAll(requests, { signal } = {}) {
  // Each thunk receives the signal as its argument. Thunks written `() => ...`
  // silently drop it, which is how every page ended up uncancellable.
  const entries = Object.entries(requests);
  const settled = await Promise.allSettled(
    entries.map(([, request]) =>
      typeof request === "function" ? request(signal) : get(request, { signal }),
    ),
  );
  const out = {};
  entries.forEach(([key], index) => {
    const result = settled[index];
    out[key] =
      result.status === "fulfilled"
        ? { ok: true, data: result.value }
        : { ok: false, error: result.reason };
  });
  return out;
}

/**
 * Endpoints.
 *
 * Every entry takes its options — crucially `signal` — as a **separate**
 * argument from its query parameters. That separation is the whole point: when
 * the two were merged, callers wrote `endpoints.events({ ...filters, signal })`
 * and the AbortSignal was serialised into the query string as
 * `signal=[object AbortSignal]`, while the request itself stayed uncancellable.
 * The gateway ignores unknown query parameters, so nothing ever failed and the
 * router's abort machinery was inert.
 */
export const endpoints = {
  overview: (params, options) => get("/api/v1/overview", { params, ...options }),
  events: (params, options) => get("/api/v1/security/events", { params, ...options }),
  event: (id, options) => get(`/api/v1/security/events/${encodeURIComponent(id)}`, options),
  latency: (params, options) => get("/api/v1/metrics/latency", { params, ...options }),
  traffic: (params, options) => get("/api/v1/metrics/traffic", { params, ...options }),
  detectors: (options) => get("/api/v1/detectors", options),
  policy: (options) => get("/api/v1/policy", options),
  system: (options) => get("/api/v1/system/status", options),
  evaluations: (options) => get("/api/v1/evaluations", options),
  evaluation: (id, options) => get(`/api/v1/evaluations/${encodeURIComponent(id)}`, options),
  session: (options) => get("/api/v1/session", options),
  ready: (options) => get("/ready", options),
};
