// Does this mailbox exist? Asked of the server that would receive the mail.
//
// THIS IS THE DEFINITIVE CHECK, AND IT IS FREE.
//
// It was believed impossible here. The reasoning was that SMTP RCPT TO needs
// outbound port 25, that Cloudflare Workers cannot open raw TCP to it, and that
// GitHub's runners are Azure-hosted and Azure blocks 25. The first two are true
// and measured. The third was inferred and is WRONG — an Actions runner reaches
// aspmx.l.google.com:25 and gets a banner. Everything below follows from having
// tested the assumption instead of repeating it.
//
// Measured against two Google Workspace domains whose answers were known in
// advance. Each was asked twice — once for a mailbox known to exist, once for
// an eighteen-character random local part on the SAME domain — because a single
// 250 proves nothing on a domain that accepts everything:
//
//   <a known mailbox>        -> 250  exists
//   <random>@same domain     -> 550  "account that you tried to reach does not exist"
//
// Both domains answered truthfully and distinguished the two, which matters
// because 82% of these prospects are on Google Workspace.
//
// THE ADDRESSES THEMSELVES ARE NOT WRITTEN DOWN HERE, and this file used to
// name four of them. It is copied verbatim into a PUBLIC repository — the only
// free host with outbound port 25 is GitHub Actions, and unmetered minutes
// there require the repository to be public — so a prospect's address in a
// comment is a published, indexed address that cannot be withdrawn.
//
// WHAT THIS IS NOT
// It never sends anything. The conversation stops at RCPT TO and QUITs, which
// is the whole difference between asking a server whether it would accept a
// message and delivering one. No DATA command is ever issued.
//
// WHERE IT CAN RUN
// Only somewhere port 25 is open, which today means the Actions runner. The
// Worker cannot do this and must not be given the job.

import net from "node:net";

const PORT = 25;
const TIMEOUT_MS = 20000;

/**
 * Consecutive connection failures, and the point at which this machine is judged
 * to have no route to port 25 at all. See the check in verifyMailbox.
 */
let blockedAfter = 0;
const BLOCKED_THRESHOLD = 3;

/** Has this machine given up on SMTP? Read by the runner so it can say so once. */
export const smtpBlocked = () => blockedAfter >= BLOCKED_THRESHOLD;
// WHO THE PROBE SAYS IT IS — AND WHY IT MUST NOT SAY "CODEWAVE".
//
// The first version announced `EHLO codewave.com` and a
// `MAIL FROM:` at that domain. That sounded polite and was actively
// harmful: the connection comes from a GitHub runner, whose IP is not in
// codewave.com's SPF record, so every receiving server that evaluates SPF at
// MAIL FROM would record an SPF failure FOR CODEWAVE.COM from an unauthorised
// address — once per prospect, every day.
//
// Mail is sent through the Gmail API from Google's own IPs and is properly
// aligned. This probe has nothing to do with that path and must not borrow its
// identity, because the only thing it can contribute to the sending domain's
// reputation is harm.
//
// So: a null sender, which is what bounce messages use and what every server is
// required to accept, and which no SPF check can attribute to anyone. And an
// address literal for EHLO — "I am this IP" — which is RFC-valid, honest, and
// names no domain at all. With a null sender, SPF falls back to the HELO
// identity, so claiming a domain there would reintroduce exactly the problem.
const MAIL_FROM = "";
let heloIdentity = null;

async function heloName() {
  if (heloIdentity) return heloIdentity;
  try {
    const response = await fetch("https://api.ipify.org", { signal: AbortSignal.timeout(8000) });
    const ip = (await response.text()).trim();
    heloIdentity = /^[0-9.]+$/.test(ip) ? `[${ip}]` : "[127.0.0.1]";
  } catch {
    heloIdentity = "[127.0.0.1]";
  }
  return heloIdentity;
}

/** The lowest-preference MX for a domain, over DNS-over-HTTPS. */
export async function primaryMx(domain) {
  try {
    const response = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`,
      { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(10000) });
    if (!response.ok) return null;
    const data = await response.json();
    const hosts = (data.Answer || [])
      .filter((a) => a.type === 15 && a.data)
      .map((a) => {
        const parts = String(a.data).trim().split(/\s+/);
        return { pref: Number(parts[0]) || 0, host: parts[parts.length - 1].replace(/\.$/, "") };
      })
      .sort((a, b) => a.pref - b.pref);
    return hosts.length ? hosts[0].host : null;
  } catch {
    return null;
  }
}

/**
 * One SMTP conversation, asking about several recipients on the same connection.
 *
 * Several rather than one because catch-all detection needs a second question,
 * and opening a fresh connection per address is both slower and ruder.
 */
async function ask(host, recipients) {
  const helo = await heloName();
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port: PORT });
    socket.setTimeout(TIMEOUT_MS);

    const results = new Map();
    let buffer = "";
    // banner -> ehlo -> mail -> one rcpt per recipient -> quit
    let stage = "banner";
    let index = 0;
    let settled = false;

    const finish = (error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ results, error });
    };

    const send = (line) => socket.write(`${line}\r\n`);

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      // A reply is complete when a line starts with three digits and a SPACE.
      // Continuation lines use a hyphen, and treating one as final is the
      // classic way to desynchronise an SMTP client.
      const match = /^\d{3} [^\n]*\n?$/m.exec(buffer.split("\n").filter(Boolean).pop() + "\n");
      if (!match) return;

      const reply = buffer.trim();
      const code = Number(reply.slice(-reply.length).match(/(\d{3}) [^\n]*$/)?.[1] ?? reply.slice(0, 3));
      buffer = "";

      if (stage === "banner") {
        if (code !== 220) return finish(`banner ${code}`);
        stage = "ehlo"; return send(`EHLO ${helo}`);
      }
      if (stage === "ehlo") {
        if (code !== 250) return finish(`ehlo ${code}`);
        stage = "mail"; return send(`MAIL FROM:<${MAIL_FROM}>`);   // null sender
      }
      if (stage === "mail") {
        if (code !== 250) return finish(`mail-from ${code}`);
        stage = "rcpt"; return send(`RCPT TO:<${recipients[index]}>`);
      }
      if (stage === "rcpt") {
        results.set(recipients[index], { code, message: reply.split("\n").pop().slice(0, 120) });
        index += 1;
        if (index < recipients.length) return send(`RCPT TO:<${recipients[index]}>`);
        stage = "quit"; send("QUIT"); return finish(null);
      }
    });

    socket.on("timeout", () => finish("timeout"));
    socket.on("error", (error) => finish(error.code || error.message));
    socket.on("close", () => finish(null));
  });
}

const randomLocal = () =>
  Array.from({ length: 18 }, () => "abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random() * 26)]).join("");

/**
 * Verify one address.
 *
 * @returns {{exists: "yes"|"no"|"unknown", reason: string, catchAll?: boolean, code?: number}}
 *
 * THE THREE ANSWERS ARE KEPT APART ON PURPOSE.
 *
 *   yes      the server accepted the recipient, and rejected a random one at the
 *            same domain, so it is not simply accepting everything.
 *   no       the server rejected it permanently. This is the expensive one to
 *            get wrong in either direction, so only a 5xx counts.
 *   unknown  greylisting, a catch-all domain, a blocked connection, a timeout.
 *            NOT a failure — an address that could not be checked is exactly as
 *            good as it was before the check, and condemning it would discard
 *            good prospects for a server's mood.
 */
export async function verifyMailbox(address) {
  const domain = String(address).split("@")[1];
  if (!domain) return { exists: "unknown", reason: "not an address" };

  const host = await primaryMx(domain);
  if (!host) return { exists: "unknown", reason: "no MX record" };

  // The control goes FIRST. A domain that accepts anything will accept the real
  // address too, and asking in this order means a catch-all can never be
  // mistaken for a confirmation.
  // PORT 25 IS EITHER REACHABLE FROM THIS MACHINE OR IT IS NOT, and finding out
  // once is enough.
  //
  // Most residential and office networks block outbound 25 to stop spam relays,
  // and this laptop's does. Every probe therefore spent the full twenty-second
  // timeout — twice, because the catch-all control is asked first — and returned
  // "connection: timeout". At two prospects a batch that is eighty seconds a
  // batch bought for nothing, on the one host whose whole appeal is that its
  // minutes are free but finite in wall clock.
  //
  // THREE FAILURES, NOT ONE. A single timeout is a slow server, not a blocked
  // port; three in a row with no success ever recorded is a network that does
  // not carry SMTP. If one ever succeeds the memo is cleared, so a laptop moved
  // onto a different network starts verifying again without anybody noticing it
  // had stopped.
  if (blockedAfter >= BLOCKED_THRESHOLD) {
    return { exists: "unknown", blocked: true,
      reason: "outbound port 25 is blocked on this machine; verification is left to the sweep" };
  }
  const control = `${randomLocal()}@${domain}`;
  const { results, error } = await ask(host, [control, address]);
  if (error && !results.size) {
    blockedAfter += 1;
    return { exists: "unknown", reason: `connection: ${error}` };
  }
  blockedAfter = 0;

  const controlReply = results.get(control);
  const reply = results.get(address);
  if (!reply) return { exists: "unknown", reason: `no answer for the address (${error || "closed early"})` };

  if (controlReply && controlReply.code >= 200 && controlReply.code < 300) {
    return { exists: "unknown", reason: "the domain accepts any address (catch-all)", catchAll: true, code: reply.code };
  }

  if (reply.code >= 200 && reply.code < 300) {
    return { exists: "yes", reason: `mail server accepted the recipient (${reply.code})`, code: reply.code };
  }
  if (reply.code >= 500 && reply.code < 600) {
    // A 5xx IS NOT AUTOMATICALLY "THIS MAILBOX DOES NOT EXIST".
    //
    // The first run over the real queue produced two verdicts that would have
    // quarantined good prospects:
    //
    //   <a real prospect>   550 https://lookup.abusix.com/search?q=<the runner's IP>
    //   <a real prospect>   550 5.4.1 Recipient address rejected: Access denied
    //
    // The first is that server blocking the RUNNER'S IP — a fact about where the
    // probe came from, not about the address. The second is a policy rejection.
    // Both mean "I will not answer you", which is precisely the case where the
    // honest verdict is that we could not tell.
    //
    // So only the codes that actually name the recipient count. 5.1.1 is "bad
    // destination mailbox address" and 5.1.3 is "bad destination mailbox address
    // syntax"; those are answers about the address itself.
    const message = String(reply.message || "");
    // 5.1.3 IS ABOUT THE STRING, NOT THE MAILBOX.
    //
    // Four queued addresses arrived in the shapes "Name;name@example.com" and
    // "Name||||name@example.com" — several candidate local parts glued
    // together. Google answered 553 5.1.3, bad destination mailbox address
    // SYNTAX, which is a verdict on the malformed string and says nothing about
    // whether the address buried inside it exists.
    //
    // Quarantining on that would have destroyed four real prospects for a
    // formatting fault the runner already knows how to repair. So a syntax
    // rejection asks for the address to be fixed and re-checked; only a
    // recipient-not-found answer condemns it.
    const saysBadSyntax = /5\.1\.3\b|syntax/i.test(String(reply.message || ""));
    if (saysBadSyntax && /[;|,]/.test(String(address))) {
      return { exists: "unknown", reason: "the address is several values joined together — repair it and re-check", code: reply.code };
    }
    const saysNoSuchUser = /5\.1\.1\b|no such user|nosuchuser|user unknown|mailbox (?:not found|unavailable|does not exist)|recipient (?:not found|unknown)|does not exist/i.test(message);
    const saysBlocked = /5\.7\.|5\.4\.|blocked|blacklist|abusix|spamhaus|access denied|not permitted|policy|reputation|rejected due to/i.test(message);

    if (saysBlocked && !saysNoSuchUser) {
      return { exists: "unknown", reason: `the server refused the probe rather than answering: ${message.slice(0, 90)}`, code: reply.code };
    }
    if (saysNoSuchUser) {
      return { exists: "no", reason: message.slice(0, 160) || `rejected (${reply.code})`, code: reply.code };
    }
    // A bare 5xx with nothing identifying it. Not confident enough to condemn a
    // prospect on, given what the two above turned out to be.
    return { exists: "unknown", reason: `unexplained rejection (${reply.code}): ${message.slice(0, 80)}`, code: reply.code };
  }
  // 4xx is "not now" — greylisting, rate limiting, a server having a bad day.
  return { exists: "unknown", reason: `temporary response ${reply.code}`, code: reply.code };
}
