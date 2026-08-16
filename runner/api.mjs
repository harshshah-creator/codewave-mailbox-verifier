// Talking to the control-plane Worker.
//
// One place for the base URL, the token and retries, so no caller invents its
// own. Failures here are reported with the real cause rather than an empty
// AggregateError, which is what an unhandled fetch failure looks like and which
// costs an hour every time it happens.

// THE ADDRESS COMES FROM THE ENVIRONMENT AND IS NOT WRITTEN DOWN HERE.
//
// It used to be a hardcoded default with AGENT_BASE as an override, which was
// convenient right up until this file was copied into a PUBLIC repository — the
// only free host with outbound port 25 is GitHub Actions, and unmetered minutes
// there require a public repo. A default is not a secret, but publishing the
// exact address of the control plane tells the internet the system exists and
// where to knock. The token still gates every call; there is simply no reason
// to hand out the door number as well.
//
// Unset is a hard failure rather than a fallback. A silent default is how a
// runner ends up talking confidently to the wrong place — or to nowhere — and
// reporting success either way.
const BASE = String(process.env.AGENT_BASE || "").replace(/\/+$/, "");

const TOKEN = process.env.MARKETING_AGENT_TOKEN || "";

const RETRYABLE = new Set([429, 500, 502, 503, 504]);

export async function api(method, path, body, { attempts = 3 } = {}) {
  if (!BASE) {
    throw new Error("AGENT_BASE is not set — this runner does not know which control plane to talk to");
  }
  if (!TOKEN) throw new Error("MARKETING_AGENT_TOKEN is not set");
  let lastError = null;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(`${BASE}${path}`, {
        method,
        headers: {
          // `x-agent-token`, not an Authorization bearer. The Worker's
          // agentAuthorised() reads this header specifically, and a bearer token
          // it never looks at produces a flat 401 that reads like a bad secret
          // rather than a header the caller sent in the wrong place.
          "x-agent-token": TOKEN,
          ...(body ? { "content-type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });

      const text = await response.text();
      let parsed = null;
      try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; }

      if (RETRYABLE.has(response.status) && attempt < attempts) {
        await sleep(attempt * 2000);
        continue;
      }
      return { status: response.status, body: parsed, raw: text };
    } catch (error) {
      // fetch() rejects for DNS and connection failures. Name the cause, because
      // the default message is frequently empty.
      lastError = new Error(`${method} ${path} failed: ${describe(error)}`);
      if (attempt < attempts) { await sleep(attempt * 2000); continue; }
      throw lastError;
    }
  }
  throw lastError || new Error(`${method} ${path} failed`);
}

export async function requireOk(method, path, body, options) {
  const result = await api(method, path, body, options);
  if (result.status < 200 || result.status >= 300) {
    throw new Error(`${method} ${path} returned HTTP ${result.status}: ${String(result.raw).slice(0, 300)}`);
  }
  return result.body;
}

function describe(error) {
  const parts = [];
  let current = error;
  while (current) {
    if (current.code) parts.push(current.code);
    if (current.message) parts.push(current.message);
    current = current.cause;
  }
  return parts.filter(Boolean).join(" — ") || String(error);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
