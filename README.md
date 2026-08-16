# Mailbox verifier

Asks a mail server whether an address exists, before anything is sent to it.

It never sends mail. Each conversation stops at `RCPT TO` and quits, which is
the difference between asking a server whether it *would* accept a message and
delivering one.

## Why it exists

Sending to an address that does not exist produces a hard bounce, and bounces
are the main thing that gets a sending domain classified as spam. One bad
address costs more than the prospect it was meant to reach.

The reliable way to avoid that is to ask the receiving server first:

```
220 mx.example.com ESMTP
EHLO …
MAIL FROM:<>
RCPT TO:<person@example.com>
250 2.1.5 OK            <- the mailbox exists
550 5.1.1 No such user  <- it does not
QUIT
```

This works for **every** provider — Google, Microsoft, Zoho, self-hosted —
because it asks the server that would actually receive the mail. There is no
per-provider trick to maintain and nothing to pay for.

## Why it is a separate, public repository

`RCPT TO` needs outbound TCP port 25, and almost nothing has it. Measured on
17 August 2026:

| Host | Port 25 | Evidence |
|---|---|---|
| Laptop / home ISP | blocked | 25, 587 and 465 filtered, IPv4 and IPv6 |
| CircleCI | blocked | no banner in 6s; matches [BreakSPF (NDSS 2024)](https://zhangmm.net/files/papers/ndss24-breakspf-4.pdf), which found CircleCI alone among CI hosts restricts outbound 25 |
| Cloudflare Workers | forbidden | "Connections to port 25 are prohibited" |
| **GitHub Actions** | **open** | real `250` and `550` responses from Google and Microsoft |

Every free-tier VPS surveyed — Oracle Always Free, GCP, AWS, Hetzner,
DigitalOcean, Vultr, Scaleway — blocks port 25 by default. GitHub Actions is the
one free host where the check runs.

The catch is that Actions minutes on **private** repositories are metered, and a
spending limit stops jobs from starting once the allowance is gone. Public
repositories are the exception: standard GitHub-hosted runners are free and
unlimited there, and spending limits govern private repositories only.

Hence a small public repository holding only the probe.

## What is here, and what deliberately is not

**Here:** a generic SMTP probe, a generic HTTPS probe, an HTTP client.

**Not here:** campaign strategy, prospect data, drafts, model prompts, send
logic. None of it is needed to ask a mail server a question, so none of it is
published.

The API token is a repository **secret**, never in the code, and the only
credential this repository touches.

Because the logs are world-readable, `PUBLIC_LOGS` is on: the sweep prints the
domain and the length of the local part, never the address itself. Actions logs
persist and are indexed, and that is not a leak that could be taken back.

## The checks, and what each one proves

| Check | Proves | Covers |
|---|---|---|
| `smtp_verify.mjs` | this exact mailbox exists | every provider |
| `entra_verify.mjs` | this exact mailbox exists in a Microsoft 365 tenant | Microsoft 365 only |

Both are guarded by a **random control address** on the same domain, asked
first. A domain that accepts anything — a catch-all, or a tenant with
enumeration protection — will claim the random address exists too, and the real
answer is then discarded as `unknown`. A `yes` is only ever returned when the
server accepts the real address and rejects a random one.

Neither check can prove an address belongs to the person named. It proves the
mailbox is live, which is what stops the bounce.

`unknown` is not a failure and never quarantines anything: greylisting, a
catch-all and a refused connection all land there, and none of them is evidence
about the address.

## Files

| File | Does |
|---|---|
| `runner/verify-queue.mjs` | the sweep: fetch unsent addresses, check each, write verdicts back |
| `runner/smtp_verify.mjs` | `RCPT TO` over port 25, with a catch-all control |
| `runner/entra_verify.mjs` | Microsoft's sign-in endpoint over HTTPS, with the same control |
| `runner/net_probe.mjs` | can this host reach port 25 at all? |
| `runner/port25-check.mjs` | prints that answer, and records it |
| `runner/api.mjs` | talking to the control-plane Worker |

These are copied from the private repository that owns them, by
`scripts/sync-verifier.sh` there. Edit them at the source, not here — the copy
that runs is this one, so a change made only upstream would silently never take
effect.

## Running it by hand

Needs `MARKETING_AGENT_TOKEN` in the environment. Report-only unless `APPLY` is
set, because writing verdicts is a decision about real prospects.

```bash
MARKETING_AGENT_TOKEN=… node runner/verify-queue.mjs
```

To check only whether this machine can reach port 25:

```bash
node runner/port25-check.mjs
```
