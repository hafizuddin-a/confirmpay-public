/**
 * Did this email really come from the bank it says it came from?
 *
 * Cloudflare's mail servers check every email before our Worker sees it: SPF (may the sender's
 * domain send), DKIM (is it signed by that domain) and DMARC (does one of those match the visible
 * From). The verdict is written into an `ARC-Authentication-Results` header. A forger can type any
 * From but cannot make a bank's signature, so "DMARC passed for dbs.com" can't be forged.
 *
 * Only the TOP-MOST such header is read: Cloudflare puts its header above everything, so anything an
 * attacker includes sits below it, and it counts only if it names `mx.cloudflare.net`. That keeps a
 * pasted-in "dmarc=pass" from counting. Import-free so the unit tests can load it.
 */

export type AuthVerdict = "verified" | "unverified" | "unknown";

export interface AuthResult {
  verdict: AuthVerdict;
  /** Short, plain-text account of what was seen, for the audit trail: authentication headers
   *  and a few counts, never the message. */
  summary: string;
}

export interface Header {
  key: string;
  value: string;
}

/** The authenticating server whose verdict we trust. */
const CLOUDFLARE_MX = "mx.cloudflare.net";

const MAX_SUMMARY = 900;

const oneLine = (s: string) => s.replace(/\s+/g, " ").trim();

interface Parsed {
  /** The ARC instance number, when the header is an ARC one. */
  instance: number | null;
  authserv: string;
  /** method -> every result seen for it, each with its `property=value` pairs. */
  results: Map<string, { result: string; props: Record<string, string> }[]>;
}

/** Splits `i=2; mx.cloudflare.net; dkim=pass header.d=dbs.com; dmarc=pass …`. */
function parseAuthResults(value: string, isArc: boolean): Parsed | null {
  const parts = oneLine(value)
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean);
  let instance: number | null = null;
  if (isArc) {
    const m = /^i=(\d+)$/i.exec(parts.shift() ?? "");
    if (!m) return null;
    instance = Number(m[1]);
  }
  const head = parts.shift();
  if (!head) return null;
  // "authserv-id [version]"
  const authserv = head.split(/\s+/)[0].toLowerCase();

  const results: Parsed["results"] = new Map();
  for (const part of parts) {
    const m = /^([a-z0-9-]+)\s*=\s*([a-z]+)\b(.*)$/i.exec(part);
    if (!m) continue;
    const props: Record<string, string> = {};
    // key=value pairs, where a value may sit in (parentheses) comments we ignore.
    for (const pm of m[3].replace(/\([^)]*\)/g, " ").matchAll(/([a-z0-9.-]+)\s*=\s*("[^"]*"|\S+)/gi)) {
      props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, "").toLowerCase();
    }
    const method = m[1].toLowerCase();
    const list = results.get(method) ?? [];
    list.push({ result: m[2].toLowerCase(), props });
    results.set(method, list);
  }
  return { instance, authserv, results };
}

/** The domain part of an address (or of `@domain`), lowercase. */
function domainOf(addr: string): string {
  return addr.slice(addr.lastIndexOf("@") + 1).trim().toLowerCase();
}

/** The `i=` of the first ARC-Seal, i.e. the newest hop. */
function topSealInstance(headers: Header[]): number | null {
  const seal = headers.find((h) => h.key === "arc-seal");
  const m = seal ? /(?:^|[;\s])i=(\d+)/i.exec(seal.value) : null;
  return m ? Number(m[1]) : null;
}

/** The `d=` of every DKIM-Signature on the message, for the audit trail. */
function dkimDomains(headers: Header[]): string[] {
  const out: string[] = [];
  for (const h of headers) {
    if (h.key !== "dkim-signature") continue;
    const m = /(?:^|[;\s])d=([^;\s]+)/i.exec(h.value);
    if (m) out.push(m[1].toLowerCase());
  }
  return out;
}

/**
 * The verdict for a message.
 *
 * @param headers the message's headers, top-most first (as postal-mime lists them)
 * @param fromAddress the address in the From header
 * @param bankDomains the domains of the bank that address claims to be from
 */
export function judgeAuth(headers: Header[], fromAddress: string, bankDomains: string[]): AuthResult {
  const seals = headers.filter((h) => h.key === "arc-seal").length;
  const facts =
    `arc-seals=${seals}; dkim-signatures=${dkimDomains(headers).join(",") || "none"}`;
  const result = (verdict: AuthVerdict, why: string, seen = ""): AuthResult => ({
    verdict,
    summary: `${why} | ${facts}${seen ? ` | ${seen}` : ""}`.slice(0, MAX_SUMMARY),
  });

  // The newest authentication header of either kind.
  const top = headers.find((h) => h.key === "arc-authentication-results" || h.key === "authentication-results");
  if (!top) return result("unknown", "no authentication header");
  const seen = `${top.key}: ${oneLine(top.value)}`;

  const isArc = top.key === "arc-authentication-results";
  const parsed = parseAuthResults(top.value, isArc);
  if (!parsed) return result("unknown", "authentication header not understood", seen);
  if (parsed.authserv !== CLOUDFLARE_MX) {
    return result("unknown", `newest authentication header is from ${parsed.authserv}, not ${CLOUDFLARE_MX}`, seen);
  }
  // A genuine ARC set is sealed at the same instance; a bare pasted-in header isn't.
  if (isArc && topSealInstance(headers) !== parsed.instance) {
    return result("unknown", "ARC instance does not match the newest seal", seen);
  }

  const dmarc = parsed.results.get("dmarc")?.[0];
  if (!dmarc) return result("unverified", "no DMARC result", seen);
  if (dmarc.result !== "pass") return result("unverified", `dmarc=${dmarc.result}`, seen);

  const headerFrom = (dmarc.props["header.from"] ?? "").replace(/^@/, "");
  const fromDomain = domainOf(fromAddress);
  const isBank = (d: string) => bankDomains.some((b) => d === b || d.endsWith("." + b));
  if (!headerFrom || headerFrom !== fromDomain) {
    return result("unverified", `dmarc passed for "${headerFrom}", but the email is from "${fromDomain}"`, seen);
  }
  if (!isBank(headerFrom)) {
    return result("unverified", `dmarc passed for ${headerFrom}, which is not this bank's domain`, seen);
  }
  return result("verified", `dmarc=pass for ${headerFrom}`, seen);
}
