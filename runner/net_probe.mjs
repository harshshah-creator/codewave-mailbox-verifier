// Can THIS machine reach port 25 at all?
//
// WHY THIS EXISTS
// "CircleCI blocks port 25" was written into this repo's comments, and into the
// decision to keep the verification sweep on GitHub, on the strength of no test
// whatsoever. The reasoning was: every definite verdict in the database is dated
// 11-14 August, GitHub ran out of minutes on the 16th, and nothing definite has
// landed since — therefore the new host must be blocked. That is inference from
// an absence, and it was wrong to record it as fact. The verdicts stopped
// because the LAPTOP took over the sweep, and the laptop's ISP is what blocks
// 25; whether CircleCI does was never once measured.
//
// The cost of guessing was not small. It sent the search for a verification host
// off to a VPS the owner does not have, when the host already wired up may have
// been able to do the job the whole time.
//
// So: measure it, in one second, and record the answer where a person and the
// dispatcher can both read it.
//
// WHAT A PASS PROVES
// A TCP connection to a well-known MX answered with an SMTP banner (220). That
// is the same first move verifyMailbox makes, so a pass here means the real
// check can run on this host. It does not prove any particular mailbox exists —
// only that the question can be asked from here.
//
// WHY IT READS THE BANNER AND DOES NOT STOP AT connect()
// A bare connect() succeeding is weaker evidence than it looks: some networks
// accept the TCP handshake at a transparent proxy and then drop the stream, so
// connect-only reports "open" on a link where every probe will still time out.
// The 220 comes from the mail server itself and cannot be forged by a middlebox
// that is not speaking SMTP.

import net from "node:net";

// Google's inbound MX. Chosen because it is the most reliably reachable mail
// server on the internet and because 82% of these prospects are on Workspace, so
// it is the exact server the real probes will be talking to.
const TARGET = "gmail-smtp-in.l.google.com";
const PORT = 25;

// Short on purpose. A blocked port fails one of two ways: a fast refusal, or
// silence until the timeout. Six seconds is long enough to cross the planet and
// read a banner, and short enough that discovering "this host cannot verify"
// costs six seconds rather than the forty minutes a full blocked sweep costs.
const TIMEOUT_MS = 6000;

/**
 * Try to open an SMTP conversation and read the greeting.
 *
 * @returns {Promise<{reachable: boolean, detail: string, ms: number}>}
 *   reachable is true only when a 220 banner arrived. Everything else — refused,
 *   timed out, connected-then-silent, a non-220 greeting — is false, with the
 *   reason kept verbatim so a person reading it later can tell a firewall from
 *   an outage.
 */
export function probePort25({ host = TARGET, port = PORT, timeoutMs = TIMEOUT_MS } = {}) {
  const started = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    const finish = (reachable, detail) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* already gone */ }
      resolve({ reachable, detail, ms: Date.now() - started });
    };

    const socket = net.createConnection({ host, port });
    socket.setTimeout(timeoutMs);
    socket.once("timeout", () => finish(false,
      `no banner from ${host}:${port} within ${timeoutMs}ms — the port is filtered or the packets are dropped`));
    socket.once("error", (error) => finish(false,
      `${host}:${port} ${error.code || ""} ${error.message || ""}`.trim()));

    let buffered = "";
    socket.on("data", (chunk) => {
      buffered += chunk.toString("utf8");
      // Wait for a complete line; a banner can arrive split across packets.
      if (!buffered.includes("\n")) return;
      const greeting = buffered.split("\n")[0].trim();
      if (greeting.startsWith("220")) {
        finish(true, `${host}:${port} answered ${greeting.slice(0, 90)}`);
      } else {
        finish(false, `${host}:${port} answered ${greeting.slice(0, 90)} instead of a 220 greeting`);
      }
    });
  });
}

/**
 * Which machine is this, by name of the provider rather than by role.
 *
 * hostProfile() answers "laptop" or "ci", which is the right split for leases
 * and budgets and the wrong one here: the whole question is whether GITHUB and
 * CIRCLECI differ, and "ci" cannot express that.
 */
export function hostLabel(env = process.env) {
  if (String(env.RUNNER_HOST || "").trim().toLowerCase() === "laptop") return "laptop";
  if (env.CIRCLECI) return "circleci";
  if (env.GITHUB_ACTIONS) return "github";
  return "unknown";
}
