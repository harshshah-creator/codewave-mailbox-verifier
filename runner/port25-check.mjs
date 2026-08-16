// Can this machine reach port 25? Ten seconds, said out loud, on every push.
//
// WHY A SEPARATE ENTRY POINT AND NOT JUST THE SWEEP
// The sweep answers this too, but only when the Worker dispatches it, which
// only happens when somebody already suspects there is a question. The belief
// this exists to correct — "outbound port 25 is very likely blocked on
// CircleCI", written into .circleci/config.yml and then quoted back as a
// finding — survived precisely because nothing cheap and automatic ever
// contradicted it. A diagnostic you have to remember to run is one you run
// after the wrong decision, not before it.
//
// It needs no arguments, no lock, no lease and no model. Checkout, npm ci,
// probe, print, record. On a blocked host it costs six seconds and saves a
// forty-minute sweep that would have produced nothing but timeouts.

import { probePort25, hostLabel } from "./net_probe.mjs";
import { api } from "./api.mjs";

const host = hostLabel();

const result = await probePort25();

console.log("");
console.log(`  host        ${host}`);
console.log(`  port 25     ${result.reachable ? "OPEN" : "BLOCKED"}`);
console.log(`  took        ${result.ms}ms`);
console.log(`  detail      ${result.detail}`);
console.log("");
console.log(result.reachable
  ? "  This host CAN verify mailboxes. SMTP RCPT TO will work here, for every"
    + "\n  provider — Google, Microsoft, self-hosted alike."
  : "  This host CANNOT verify mailboxes over SMTP. Only the HTTPS checks will"
    + "\n  return anything here, and those cover Microsoft 365 only.");
console.log("");

// Recorded so the dispatcher can act on it, not just a person reading logs.
// Best-effort on purpose: the printed answer above is the point, and a missing
// token or an undeployed endpoint must not turn a diagnostic into a red build.
if (process.env.MARKETING_AGENT_TOKEN) {
  const response = await api("POST", "/agent/host-capability", {
    host, port25: result.reachable, detail: result.detail, ms: result.ms,
  }).catch((error) => ({ status: 0, raw: error.message }));
  console.log(response.status >= 200 && response.status < 300
    ? `  Recorded against "${host}".`
    : `  Not recorded (HTTP ${response.status}): ${String(response.raw).slice(0, 120)}`);
} else {
  console.log("  Not recorded: MARKETING_AGENT_TOKEN is not set on this host.");
}

// ALWAYS EXIT ZERO. A blocked port is a fact about a network, not a broken
// build, and a red pipeline here would train everyone to ignore it.
process.exit(0);
