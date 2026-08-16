// Does this exact mailbox exist? Asked over HTTPS, so it works where SMTP cannot.
//
// WHY THIS EXISTS ALONGSIDE smtp_verify
// The SMTP probe needs outbound port 25, which residential and many office
// networks block outright — this laptop's does, on 25, 587 and 465, over both
// IPv4 and IPv6. So the one free check that proves a mailbox exists could not
// run on the very host whose whole appeal is free, unlimited passes.
//
// Microsoft's own sign-in endpoint answers the same question over port 443.
// GetCredentialType is what the Office 365 login page calls before it shows a
// password box: it says whether an account exists in the tenant. It is a
// documented, unauthenticated endpoint and needs no key.
//
//   POST https://login.microsoftonline.com/common/GetCredentialType
//   {"Username": "person@company.com"}
//     IfExistsResult: 0  -> the account exists
//     IfExistsResult: 1  -> it does not
//
// WHAT IT PROVES, AND WHAT IT DOES NOT
//   proves    this exact mailbox exists in this Microsoft 365 tenant.
//   does NOT  prove it belongs to the person named — same limit as SMTP.
//   covers    only domains hosted on Microsoft 365. A Google Workspace or
//             self-hosted domain gets "unknown"; nothing is claimed about it.
//
// THE CATCH, AND THE CONTROL THAT NEUTRALISES IT
// A tenant can enable enumeration protection, which returns "exists" for every
// address so an attacker cannot map its users. That would be a false positive.
// So, exactly like smtp_verify's catch-all control, this asks about a RANDOM
// eighteen-character address on the same domain first. If the tenant claims the
// random address exists too, it is protected and the real answer is discarded as
// "unknown". A "yes" is only ever returned when the tenant says the real address
// exists AND the random one does not.
//
// Verified against a real Microsoft 365 tenant: the target address returned 0
// (exists), a random local part on the same domain returned 1 (does not), and
// the mailbox was confirmed without touching a mail port.
//
// The tenant is not named here, and neither is the address. This file is copied
// verbatim into a public repository, so a domain in a comment is a customer
// relationship published and indexed.

const ENDPOINT = "https://login.microsoftonline.com/common/GetCredentialType";
const TIMEOUT_MS = 10000;

const randomLocal = () =>
  Array.from({ length: 18 }, () => "abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random() * 26)]).join("");

/** One GetCredentialType call. Returns the IfExistsResult, or null on any failure. */
async function ifExists(username) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ Username: username, isOtherIdpSupported: true }),
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const body = await res.json().catch(() => null);
    const r = body?.IfExistsResult;
    return typeof r === "number" ? r : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Ask Microsoft whether a mailbox exists, with a random control to defeat
 * enumeration protection.
 *
 * @returns {{exists: "yes"|"unknown", reason: string, method: "entra"}}
 *   Never returns "no": a "does not exist" from this endpoint is not reliable
 *   enough to quarantine on — a mistyped-but-real address, or a tenant quirk,
 *   would wrongly kill a good prospect. Only a clean, control-checked "yes" is
 *   acted on; everything else is left for another method or a human.
 */
export async function verifyViaEntra(address) {
  const domain = String(address || "").split("@")[1];
  if (!domain) return { exists: "unknown", reason: "not an address", method: "entra" };

  // The control FIRST, so a protected tenant can never be read as a confirmation.
  const control = `${randomLocal()}@${domain}`;
  const controlResult = await ifExists(control);
  if (controlResult === null) {
    return { exists: "unknown", reason: "the sign-in endpoint did not answer", method: "entra" };
  }
  if (controlResult === 0) {
    // A random address "exists" -> either a non-M365 domain the endpoint answers
    // 0 for by default, or a tenant with enumeration protection. Either way its
    // answers carry no information.
    return { exists: "unknown", reason: "the tenant answers for any address (protected or not M365)", method: "entra" };
  }

  const real = await ifExists(String(address));
  if (real === null) {
    return { exists: "unknown", reason: "the sign-in endpoint did not answer for the address", method: "entra" };
  }
  if (real === 0) {
    return { exists: "yes",
      reason: "Microsoft 365 confirms this mailbox exists in the tenant (a random control address does not)",
      method: "entra" };
  }
  // real === 1, control === 1: the tenant distinguishes, and says this one does
  // not exist. Recorded as unknown rather than no, per the contract above.
  return { exists: "unknown", reason: "Microsoft 365 does not list this mailbox in the tenant", method: "entra" };
}
