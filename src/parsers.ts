/**
 * Deterministic per-bank regex parsers for PayNow-received emails, one per sender domain. No LLM:
 * this is a payments path, so auditability and zero hallucination risk are the point.
 * DBS / UOB / OCBC patterns were seen in real notifications; the rest are best-effort and must be
 * checked against a genuine one before an org relies on them. A miss leaves amount/reference
 * null and the org confirms by hand, never a wrong match.
 */

/** What an email from a bank is: money arriving, money leaving (or a card
 *  spend, a debit), or anything else (a statement, an offer, a code). */
export type MailKind = "incoming" | "outgoing" | "other";

export interface BankHit {
  bankId: string;
  /** SGD, commas stripped. null if no amount pattern matched. */
  amount: number | null;
  /** null if no reference pattern matched. */
  reference: string | null;
  /** The payer's name as printed in the notification. null if not found. */
  payerName: string | null;
  /** Whether this reads as an incoming-payment notice; only "incoming" may be matched on amount
   *  alone, since a card-spend alert or statement also contains "SGD 20.00". */
  kind: MailKind;
}

interface Parser {
  bankId: string;
  domains: string[];
  amount?: RegExp[];
  reference?: RegExp[];
  payerName?: RegExp[];
}

// Tolerant shared amount patterns, tried in order. Each must anchor on a label
// or a currency marker so stray numbers in the body can't match.
const AMOUNT_FALLBACKS: RegExp[] = [
  /Amount\s*\(SGD\)\s*[:\-]?\s*([\d,]+\.\d{2})/i,
  /(?:Amount|Amount received|Transfer amount|Incoming (?:amount|transfer))\D{0,15}?([\d,]+\.\d{2})/i,
  /(?:SGD|S\$|\$)\s{0,3}([\d,]+\.\d{2})/i,
];

/** What a reference looks like once the label is out of the way. */
const REFERENCE_VALUE = "([A-Za-z0-9][A-Za-z0-9-]{2,})";

/**
 * "<label>: <reference>", with the label a whole word: a loose "Ref" matched the start of
 * "Referral", and the first match wins. `label` is regex source.
 */
function labelled(label: string): RegExp {
  return new RegExp(String.raw`\b(?:${label})(?![A-Za-z])\s*[:\-]?\s*${REFERENCE_VALUE}`, "i");
}

const REFERENCE_FALLBACKS: RegExp[] = [
  labelled(String.raw`Bill Reference|Recipient Reference|Reference No\.?|Reference Number|Reference|Transaction Ref\.?|Ref\.? No\.?|Ref`),
];

// The payer's name, printed on notifications with no bill-reference field. Requires a "To:"
// shortly after (a newline, or the space left by flattening HTML), so the forward wrapper's
// quoted "From:" header isn't mistaken for it.
const PAYER_NAME_FALLBACKS: RegExp[] = [
  /(?:From|Payer|Sender|Remitter)\s*[:\-]?\s*([^\n\r]{2,80}?)\s+To\s*[:\-]/i,
];

const PARSERS: Parser[] = [
  {
    bankId: "dbs",
    domains: ["dbs.com", "dbs.com.sg", "posb.com.sg"],
    reference: [labelled(String.raw`(?:Reference|Ref)(?:\s*(?:No\.?|Number))?`)],
  },
  {
    bankId: "uob",
    domains: ["uob.com.sg"],
    amount: [/Amount\s*\(SGD\)\s*[:\-]?\s*([\d,]+\.\d{2})/i],
    reference: [labelled("Bill Reference")],
  },
  {
    bankId: "ocbc",
    domains: ["ocbc.com", "ocbc.com.sg"],
    reference: [labelled(String.raw`Reference No\.?`)],
  },
  {
    bankId: "sc",
    domains: ["standardchartered.com", "standardchartered.com.sg"],
    reference: [labelled(String.raw`(?:Reference|Transaction Ref)(?:\s*No\.?)?`)],
  },
  {
    bankId: "maybank",
    domains: ["maybank.com.sg", "maybank2u.com.sg"],
    reference: [labelled(String.raw`(?:Reference|Ref No)\.?`)],
  },
  {
    bankId: "hsbc",
    domains: ["hsbc.com.sg"],
    reference: [labelled(String.raw`(?:Reference|Narrative)(?:\s*No\.?)?`)],
  },
  {
    bankId: "citi",
    domains: ["citibank.com", "citibank.com.sg", "citi.com"],
  },
  {
    bankId: "cimb",
    domains: ["cimb.com", "cimbbank.com.sg"],
    reference: [labelled(String.raw`(?:Recipient Reference|Reference)\.?`)],
  },
  {
    bankId: "trust",
    domains: ["trustbank.sg"],
  },
  {
    bankId: "gxs",
    domains: ["gxs.com.sg"],
  },
];

export interface ForwardingConfirmHit {
  provider: string;
  confirmUrl: string;
}

/**
 * Detects a mail provider's own "confirm this forwarding rule" email, sent to {token}@confirmpay.link
 * when an org sets up forwarding (the address isn't a mailbox anyone can open). Only Gmail's
 * format is known: matching "vf-" keeps it from grabbing the "uf-" cancel link. An unmatched
 * provider falls through to bank parsing, which finds nothing and logs an unmatched entry.
 */
export function detectForwardingConfirmation(
  sender: string,
  body: string,
): ForwardingConfirmHit | null {
  if (sender.toLowerCase() === "forwarding-noreply@google.com") {
    const m = body.match(/https:\/\/mail\.google\.com\/mail\/vf-\S+/);
    if (m) return { provider: "Gmail", confirmUrl: m[0] };
  }
  return null;
}

const NAMED_ENTITIES: Record<string, string> = {
  nbsp: " ",
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  // Banks pad the preview text with these; they mean nothing to a reader.
  zwnj: "",
  zwj: "",
};

/** `&amp;`, `&#160;` and `&#xA0;` as the characters they stand for. */
function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,6});/gi, (whole, e: string) => {
    if (e[0] === "#") {
      const cp = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return cp > 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) ? String.fromCodePoint(cp) : " ";
    }
    return NAMED_ENTITIES[e.toLowerCase()] ?? whole;
  });
}

/**
 * The readable text of an HTML email, on one line. Tags go first and entities are decoded after,
 * so an escaped "&lt;b&gt;" stays text. Banks put `&#160;` between "SGD" and the figure as often
 * as `&nbsp;`, so both must be understood for "SGD&#160;10.00" to match an amount.
 */
export function stripHtml(html: string): string {
  return decodeEntities(
    html
      // Comments are never shown, so nothing in one is part of the message (DBS leaves a
      // commented-out row in its template, and anyone could hide a figure in one).
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/[\u200b-\u200d\u2060\ufeff]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function firstMatch(res: RegExp[], body: string): string | null {
  for (const re of res) {
    const m = body.match(re);
    if (m?.[1]) return m[1];
  }
  return null;
}

/** The parser for the bank this address belongs to: its domain is one of the bank's or a
 *  subdomain of one. `dbs.com@evil.example`, `notdbs.com` and `dbs.com.evil.example` are not. */
function parserFor(sender: string): Parser | undefined {
  const s = sender.trim().toLowerCase();
  const at = s.lastIndexOf("@");
  if (at < 1) return undefined; // not an address
  const domain = s.slice(at + 1);
  return PARSERS.find((p) => p.domains.some((d) => domain === d || domain.endsWith("." + d)));
}

export function isTrustedSender(sender: string): boolean {
  return parserFor(sender) !== undefined;
}

// What banks say when money arrives, and when it goes the other way. Taken from real DBS
// notifications ("You have received SGD 10.00 via PayNow"); other banks' wording is a best guess,
// so their emails may not read as "incoming" and then need a reference to be matched.
const INCOMING = /\byou(?:[\u2019']ve| have)\s+received\b|\b(?:has been |was |is )credited\b|\bcredited to your\b|\bincoming\s+(?:paynow|payment|transfer|funds)\b|\breceived\s+(?:a\s+)?(?:paynow|payment|transfer|funds)\b/i;
const OUTGOING = /\byou(?:[\u2019']ve| have)\s+(?:sent|paid|transferred|made|withdrawn|spent)\b|\bdebited\b|\bcard transaction\b|\btransaction of\b|\bwithdrawal\b/i;

/**
 * Reads the subject and body for which way the money went: any sign of money out is "outgoing",
 * money in alone is "incoming", anything else (statements, offers, codes) is "other".
 */
export function classifyBankEmail(subject: string, body: string): MailKind {
  const text = `${subject}\n${body}`;
  if (OUTGOING.test(text)) return "outgoing";
  return INCOMING.test(text) ? "incoming" : "other";
}

/** The domains of the bank this address belongs to, or [] if it isn't one. */
export function bankDomainsFor(sender: string): string[] {
  return parserFor(sender)?.domains ?? [];
}

/**
 * Returns a hit for any trusted sender (amount/reference may be null if nothing matched this
 * format), or null when the sender isn't a trusted bank.
 */
export function parseBankEmail(sender: string, body: string, subject = ""): BankHit | null {
  const parser = parserFor(sender);
  if (!parser) return null;

  const refStr = firstMatch(
    [...(parser.reference ?? []), ...REFERENCE_FALLBACKS],
    body,
  );
  const amtStr = firstMatch(
    [...(parser.amount ?? []), ...AMOUNT_FALLBACKS],
    body,
  );
  const amt = amtStr != null ? Number(amtStr.replace(/,/g, "")) : NaN;

  const nameStr = firstMatch(
    [...(parser.payerName ?? []), ...PAYER_NAME_FALLBACKS],
    body,
  );
  const payerName = nameStr ? nameStr.replace(/\s+/g, " ").trim().slice(0, 80) || null : null;

  return {
    bankId: parser.bankId,
    amount: Number.isFinite(amt) ? amt : null,
    reference: refStr,
    payerName,
    kind: classifyBankEmail(subject, body),
  };
}
