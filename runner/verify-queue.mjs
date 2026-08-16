// Ask every queued address's own mail server whether it exists.
//
// WHY THIS RUNS HERE AND NOT IN THE WORKER
// It needs outbound port 25. Cloudflare Workers cannot open raw TCP to it; an
// Actions runner can, which was the discovery that made any of this possible.
// The Worker therefore cannot own this job however much it would like to.
//
// WHAT IT DOES WITH EACH ANSWER
//   no        the receiving server says the mailbox does not exist. That mail
//             would bounce, and bounces are what get a sending domain
//             classified as spam. Quarantined with the server's own words.
//   yes       recorded as verified, and the record carries the proof. This can
//             rescue an address that was refused earlier for being inferred:
//             "I worked this out" plus "the server confirms it exists" is no
//             longer a guess.
//   unknown   left exactly as it was. Greylisting, a catch-all domain and a
//             refused connection all land here, and none of them are evidence
//             about the address. Treating them as failure would discard good
//             prospects for a server's mood.

import { api, requireOk } from "./api.mjs";
import { verifyMailbox } from "./smtp_verify.mjs";
import { verifyViaEntra } from "./entra_verify.mjs";
import { probePort25, hostLabel } from "./net_probe.mjs";

const APPLY = String(process.env.APPLY || "").toLowerCase() === "true";
const HOST = hostLabel();
const log = (message) => console.log(`[${new Date().toISOString()}] ${message}`);

// THIS JOB LOGS THE ONE FIELD THAT IS PURE PERSONAL DATA — a prospect's email
// address, one line each, for the whole queue.
//
// research.mjs has redacted under PUBLIC_LOGS since the runner was built. This
// file never did, which did not matter while every host running it was a
// private repository or a laptop. It stops being true the moment verification
// moves somewhere with world-readable logs, and that is precisely the direction
// the search for an unblocked host is heading: the only free host with port 25
// open is GitHub Actions, and the only way to get unmetered minutes there is a
// PUBLIC repository.
//
// So the redaction lands before the move, not after. Actions logs persist and
// are indexed, and a leak here cannot be withdrawn.
//
// The domain is kept, because it is the diagnostic half — "every address at
// this domain came back unknown" is the shape of a catch-all or a greylisting
// server, and losing it would make public runs undebuggable. The local part is
// the personal half and is what goes.
const PUBLIC_LOGS = /^(1|true|yes)$/i.test(String(process.env.PUBLIC_LOGS || "").trim());
const shown = (address) => {
  if (!PUBLIC_LOGS) return String(address);
  const [local, domain] = String(address).split("@");
  return domain ? `<${local ? local.length : 0} chars>@${domain}` : "<address>";
};

// Politeness. These are other people's mail servers and there is no hurry: the
// whole queue is a few dozen addresses and this runs once a day.
const PAUSE_MS = 1500;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  // BEFORE ANYTHING ELSE: can this machine do the job at all?
  //
  // A sweep on a host without port 25 is not a failure that announces itself —
  // it is forty minutes of timeouts producing a page of "could not tell", which
  // looks identical to a run where every mail server happened to be unhelpful.
  // That ambiguity is what let "CircleCI blocks port 25" sit in this repo as an
  // asserted fact for days without anyone measuring it.
  //
  // Six seconds, once, at the top. The answer is reported to the Worker whatever
  // it is, so the dispatcher stops sending verification to hosts that cannot
  // perform it and a person can read which hosts can.
  const net = await probePort25();
  log(`host=${HOST}  port 25 ${net.reachable ? "OPEN" : "BLOCKED"} (${net.ms}ms) — ${net.detail}`);
  await api("POST", "/agent/host-capability", {
    host: HOST, port25: net.reachable, detail: net.detail, ms: net.ms,
  }).catch((error) => log(`  (could not record capability: ${error.message})`));

  const reports = (await requireOk("GET", "/agent/reports")).reports || [];
  const pending = reports.filter((r) =>
    !r.sentAt && r.email?.recipient && !["closed", "sent"].includes(String(r.status || "")));

  log(`${pending.length} unsent address(es) to check. apply=${APPLY}`);

  const tally = { yes: 0, no: 0, unknown: 0 };
  const changed = [];

  for (const report of pending) {
    const address = report.email.recipient;
    // Entra first (HTTPS, works where port 25 is blocked), SMTP as the fallback
    // and the only path that can return a definite "no". A "yes" from either is
    // proof; see the research pass for the same ordering.
    let result = await verifyViaEntra(address).catch(() => ({ exists: "unknown", reason: "entra failed" }));
    // SMTP only where SMTP can reach. On a blocked host every one of these costs
    // a full 20-second timeout and returns nothing — an hour of the sweep's
    // budget spent proving the same firewall over and over. Entra still ran
    // above, so a Microsoft-hosted address is still confirmed here.
    if (result.exists !== "yes" && net.reachable) {
      const smtp = await verifyMailbox(address).catch(() => ({ exists: "unknown", reason: "smtp failed" }));
      if (smtp.exists === "no" || smtp.exists === "yes") result = smtp;
    }
    tally[result.exists] += 1;
    log(`  ${result.exists.toUpperCase().padEnd(7)} ${shown(address).padEnd(38)} ${result.reason.slice(0, 72)}`);

    if (result.exists === "no") {
      changed.push({
        id: report.id,
        patch: {
          status: "quarantined",
          scheduledSendAt: "",
          needsAttention: `the mail server says this mailbox does not exist: ${result.reason.slice(0, 120)}`,
          mailboxCheck: { exists: "no", host: HOST, checkedAt: new Date().toISOString(), reason: result.reason.slice(0, 200) },
        },
      });
    } else if (result.exists === "yes") {
      changed.push({
        id: report.id,
        patch: {
          mailboxCheck: { exists: "yes", method: result.method || "smtp", host: HOST, checkedAt: new Date().toISOString(), reason: result.reason.slice(0, 200) },
        },
      });
    } else {
      // AN INCONCLUSIVE CHECK IS STILL A CHECK, and recording nothing made
      // "never attempted" and "attempted, server unhelpful" identical in the
      // data. Five approved drafts sat blocked on 16 August reading "never
      // checked" and there was no way to tell whether the sweep had reached
      // them at all — which is the difference between "wait" and "this will
      // never resolve, go and find another address".
      //
      // The VERDICT is still not recorded: `exists` stays unknown, so nothing
      // downstream treats a greylisting server or a catch-all domain as
      // evidence about the address. Only the attempt is written.
      changed.push({
        id: report.id,
        patch: {
          mailboxCheck: {
            exists: "unknown",
            host: HOST,
            checkedAt: new Date().toISOString(),
            attempts: Number(report.mailboxCheck?.attempts || 0) + 1,
            reason: result.reason.slice(0, 200),
          },
        },
      });
    }

    await sleep(PAUSE_MS);
  }

  log("");
  log(`exists ${tally.yes}   does not exist ${tally.no}   could not tell ${tally.unknown}`);

  if (!APPLY) {
    log("Report only. Re-run with apply: true to write these verdicts back.");
    return;
  }

  let written = 0;
  for (const { id, patch } of changed) {
    const result = await api("POST", "/agent/mailbox-check", { id, ...patch });
    if (result.status >= 200 && result.status < 300) written += 1;
    else log(`  could not update ${id}: HTTP ${result.status}`);
  }
  log(`${written} record(s) updated.`);
}

main().catch((error) => {
  log(`FAILED: ${error.message}`);
  process.exit(1);
});
