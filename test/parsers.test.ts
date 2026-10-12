/**
 * Parser checks. Run: npm test
 *
 * Bodies are representative, not captured from real notifications. Names, account digits,
 * references, addresses and links are made up; keep real ones out of this file.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseBankEmail,
  isTrustedSender,
  detectForwardingConfirmation,
  stripHtml,
  classifyBankEmail,
  bankDomainsFor,
} from "../src/parsers.ts";

const cases: {
  name: string;
  sender: string;
  body: string;
  amount: number | null;
  reference: string | null;
  payerName: number | null | string;
}[] = [
  {
    name: "DBS — 'Amount: SGD 20.00'",
    sender: "notify@dbs.com",
    body: "You have received an incoming PayNow transfer.\nAmount: SGD 20.00\nFrom: JOHN TAN\nReference: DON-014\n",
    amount: 20,
    reference: "DON-014",
    // No "To:" line follows "From: JOHN TAN" here, so the anchored pattern
    // correctly declines to guess — this case is about amount/reference, not name.
    payerName: null,
  },
  {
    name: "DBS — mobile PayNow notification with no bill reference at all",
    sender: "notify@dbs.com",
    body: [
      "digibank Alerts - You've received a transfer",
      'Problems viewing this email? Select "always display images"',
      "",
      "Transaction Ref: 1700000000000000000000C100000000000",
      "",
      "Dear Customer,",
      "",
      "You have received SGD 10.00 via PayNow on 11 Sep 2026 20:21 SGT.",
      "",
      "From: SITI SOFIA BINTE ABDUL KARIM",
      "To: Your DBS/ POSB account ending 1234",
      "",
      "Didn't expect these funds? If this is a joint account, it may be for your joint account holder. Otherwise, please call our DBS hotline.",
      "",
      "Thank you for banking with us.",
      "",
      "Yours faithfully",
      "DBS Bank Ltd",
    ].join("\n"),
    amount: 10,
    // DBS's own transaction ID, not a ConfirmPay reference: extracted (it matches the generic
    // "Transaction Ref:" label) but harmless, since it never equals a real request reference and
    // intake falls through to amount/name matching.
    reference: "1700000000000000000000C100000000000",
    payerName: "SITI SOFIA BINTE ABDUL KARIM",
  },
  {
    name: "DBS — 'Amount: S$1,250.00'",
    sender: "ibanking.alert@dbs.com",
    body: "Amount: S$1,250.00\nReference No.: EVENT-2026-07\n",
    amount: 1250,
    reference: "EVENT-2026-07",
    payerName: null,
  },
  {
    name: "POSB — bare number",
    sender: "alert@posb.com.sg",
    body: "Transfer amount 45.50 received. Ref: KID-0093.",
    amount: 45.5,
    reference: "KID-0093",
    payerName: null,
  },
  {
    name: "UOB — 'Amount (SGD): 30.00' + 'Bill Reference:'",
    sender: "no-reply@uob.com.sg",
    body: "Amount (SGD): 30.00\nBill Reference: MASJID-114\n",
    amount: 30,
    reference: "MASJID-114",
    payerName: null,
  },
  {
    name: "OCBC — 'Reference No.:'",
    sender: "notification@ocbc.com",
    body: "You've received SGD 12.00 via PayNow.\nReference No.: DON-002\n",
    amount: 12,
    reference: "DON-002",
    payerName: null,
  },
  {
    name: "Standard Chartered",
    sender: "alerts@standardchartered.com",
    body: "Incoming transfer SGD 88.00. Transaction Ref: SC-771.",
    amount: 88,
    reference: "SC-771",
    payerName: null,
  },
  {
    name: "HTML email, flattened to one line — From/To still adjacent enough to match",
    sender: "notify@dbs.com",
    body: "You have received SGD 5.00 via PayNow. From: TAN AH KOW To: Your DBS account ending 1234.",
    amount: 5,
    reference: null,
    payerName: "TAN AH KOW",
  },
  {
    name: "a forwarded email's own quoted header must not be mistaken for the payer",
    sender: "notify@dbs.com",
    body: "From: DBS Bank <alerts@dbs.com>\nDate: 11 Sep 2026\nSubject: You've received a transfer\n\nYou have received SGD 10.00 via PayNow.\nFrom: SOFIA TAN\nTo: Your account.\n",
    amount: 10,
    reference: null,
    payerName: "SOFIA TAN",
  },
  {
    name: "unknown sender -> null",
    sender: "friend@example.com",
    body: "Amount: SGD 20.00 Reference: DON-014",
    amount: null,
    reference: null,
    payerName: null,
  },
];

for (const c of cases) {
  test(c.name, () => {
    const hit = parseBankEmail(c.sender, c.body);
    if (
      c.amount === null &&
      c.reference === null &&
      c.payerName === null &&
      !isTrustedSender(c.sender)
    ) {
      assert.equal(hit, null);
      return;
    }
    assert.ok(hit, "expected a hit for a trusted sender");
    assert.equal(hit.amount, c.amount, "amount");
    assert.equal(hit.reference, c.reference, "reference");
    assert.equal(hit.payerName, c.payerName, "payerName");
  });
}

test("loose reference never coerces a false value on prose", () => {
  const hit = parseBankEmail(
    "notify@dbs.com",
    "Please refer to your monthly statement. No action needed.",
  );
  assert.ok(hit);
  assert.equal(hit.reference, null);
});

// The shape of Gmail's "confirm forwarding to {token}@confirmpay.link" email, with the
// address, token and links replaced by placeholders.
const GMAIL_FORWARDING_BODY = [
  "treasurer@example.org has requested to automatically forward mail to your email",
  "address a1b2c3d4e5f6a1b2c3d4@confirmpay.link.",
  "",
  "To allow treasurer@example.org to automatically forward mail to your address,",
  "please click the link below to confirm the request:",
  "",
  "https://mail.google.com/mail/vf-%5BEXAMPLE-CONFIRM-CODE%5D-EXAMPLE",
  "",
  "If you click the link and it appears to be broken, please copy and paste it",
  "into a new browser window.",
  "",
  "Thanks for using Gmail!",
  "",
  "Sincerely,",
  "",
  "The Gmail Team",
  "",
  "If you do not approve of this request, no further action is required.",
  "treasurer@example.org cannot automatically forward messages to your email address",
  "unless you confirm the request by clicking the link above. If you accidentally",
  "clicked the link, but you do not want to allow treasurer@example.org to",
  "automatically forward messages to your address, click this link to cancel this",
  "verification:",
  "https://mail.google.com/mail/uf-%5BEXAMPLE-CANCEL-CODE%5D-EXAMPLE",
].join("\n");

test("detects a Gmail forwarding-confirmation email and grabs the vf- (confirm) link, not uf- (cancel)", () => {
  const hit = detectForwardingConfirmation("forwarding-noreply@google.com", GMAIL_FORWARDING_BODY);
  assert.ok(hit);
  assert.equal(hit.provider, "Gmail");
  assert.ok(hit.confirmUrl.startsWith("https://mail.google.com/mail/vf-"));
  assert.ok(!hit.confirmUrl.includes("/mail/uf-"));
});

test("forwarding-confirmation detection ignores everything else", () => {
  assert.equal(detectForwardingConfirmation("notify@dbs.com", GMAIL_FORWARDING_BODY), null);
  assert.equal(
    detectForwardingConfirmation("forwarding-noreply@google.com", "unrelated body, no link here"),
    null,
  );
});

// Regressions from the code audit.

test("a word that merely starts with 'Ref' is not a reference label", () => {
  // "Referral" used to be read as label "Ref" + reference "erral".
  for (const word of ["Referral", "Referred", "Preference", "References"]) {
    const hit = parseBankEmail("notify@dbs.com", `${word}: your friend\nAmount: SGD 8.00\n`);
    assert.ok(hit);
    assert.equal(hit.reference, null, word);
    assert.equal(hit.amount, 8, word);
  }
});

test("an earlier look-alike word does not hide the real reference line", () => {
  const hit = parseBankEmail(
    "notify@dbs.com",
    "Referral bonus inside! Invite a friend.\nYou have received SGD 20.00 via PayNow.\nReference: DON-014\n",
  );
  assert.ok(hit);
  assert.equal(hit.reference, "DON-014");
});

test("labels still match in any case and with the usual separators", () => {
  for (const [body, want] of [
    ["REFERENCE: DON-014", "DON-014"],
    ["reference - DON-014", "DON-014"],
    ["Reference No.: DON-014", "DON-014"],
    ["Reference Number DON-014", "DON-014"],
    ["Ref: DON-014", "DON-014"],
    ["Bill Reference:DON-014", "DON-014"],
  ] as const) {
    assert.equal(parseBankEmail("notify@dbs.com", body)?.reference, want, body);
  }
});

test("only a bank's own domain (or a subdomain of it) counts as that bank", () => {
  for (const ok of ["notify@dbs.com", "ibanking.alert@dbs.com.sg", "a@alerts.uob.com.sg", "A@DBS.COM", "x@posb.com.sg"]) {
    assert.ok(isTrustedSender(ok), ok);
  }
  for (const no of [
    "dbs.com@evil.example", // the bank's domain used as the *name*
    "someone@notdbs.com",
    "someone@dbs.com.evil.example",
    "someone@evil-uob.com.sg",
    "dbs.com",
    "",
  ]) {
    assert.ok(!isTrustedSender(no), no);
    assert.equal(parseBankEmail(no, "Amount: SGD 20.00 Reference: DON-014"), null, no);
  }
});

test("HTML email: numeric and named entities are decoded, not just &nbsp;", () => {
  // "SGD&#160;10.00" read as one run of text used to hide the amount.
  const text = stripHtml("<p>You have received SGD&#160;10.00&nbsp;via PayNow.</p><p>Reference:&#xA0;DON&#45;014</p>");
  assert.equal(text, "You have received SGD 10.00 via PayNow. Reference: DON-014");
  const hit = parseBankEmail("notify@dbs.com", text);
  assert.equal(hit?.amount, 10);
  assert.equal(hit?.reference, "DON-014");
});

test("stripHtml: tags go before entities are decoded, bad entities and zero-width marks are harmless", () => {
  assert.equal(stripHtml("a &lt;b&gt;bold&lt;/b&gt; &amp; &quot;q&quot;"), 'a <b>bold</b> & "q"');
  assert.equal(stripHtml("<style>.x{color:red}</style>S$<span>\u200b</span>5.00"), "S$ 5.00");
  assert.equal(stripHtml("&#0; &#xD800; &#1114112; &bogus;"), "&bogus;");
  assert.equal(stripHtml("SGD\u200b 7.00"), "SGD 7.00");
});

test("amount: a couple of spaces between the currency and the figure are fine", () => {
  assert.equal(parseBankEmail("notify@dbs.com", "received SGD   15.00 today")?.amount, 15);
});

// The parser used to read the first "SGD x.xx" in any email from a bank, so a
// card-spend alert for S$20 could confirm a pending S$20 request.
test("only an incoming-payment notice is 'incoming'", () => {
  const cases: [string, string, string][] = [
    ["incoming", "digibank Alerts - You've received a transfer", "You have received SGD 10.00 via PayNow on 11 Sep 2026."],
    ["incoming", "", "You\u2019ve received SGD 5.00 via PayNow."],
    ["incoming", "PayNow payment received", "Incoming PayNow payment of SGD 12.00 was credited to your account."],
    ["outgoing", "digibank Alerts - You've made a transfer", "You have sent SGD 20.00 via PayNow to JOHN TAN."],
    ["outgoing", "Card transaction alert", "A card transaction of SGD 20.00 was made at CAFE ABC."],
    ["outgoing", "", "SGD 20.00 has been debited from your account."],
    ["other", "Your statement is ready", "Minimum payment due: SGD 20.00 by 25 Oct."],
    ["other", "Cashback", "Earn up to $20.00 cashback this month. T&Cs apply."],
    ["other", "Your one-time password", "Your OTP is 482915. Amount: SGD 20.00"],
    // money moving both ways in one email is not a payment *to* you
    ["outgoing", "", "You have sent SGD 20.00. The recipient has received it."],
  ];
  for (const [want, subject, body] of cases) {
    assert.equal(classifyBankEmail(subject, body), want, `${subject} / ${body}`);
  }
});

test("parseBankEmail reports the kind, using the subject too", () => {
  assert.equal(parseBankEmail("notify@dbs.com", "You have received SGD 10.00 via PayNow.")?.kind, "incoming");
  assert.equal(parseBankEmail("notify@dbs.com", "SGD 20.00", "digibank Alerts - You've received a transfer")?.kind, "incoming");
  assert.equal(parseBankEmail("notify@dbs.com", "A card transaction of SGD 20.00 was made.")?.kind, "outgoing");
  assert.equal(parseBankEmail("notify@dbs.com", "Amount: SGD 20.00 Reference: DON-014")?.kind, "other");
});

test("the real DBS notification, HTML only, with its commented-out row and zero-width padding", () => {
  // Shaped like the real email (HTML part only, a commented-out "Transactional
  // Alerts" row, &zwnj; preview padding, a narrow no-break space after "From:"),
  // with the names and numbers swapped for made-up ones.
  const html = `<html><head><title>digibank Alerts - You've received a transfer</title></head><body>
<div style="display:none"> &zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp; </div>
<table><!--tr><td>Transactional Alerts</td></tr-->
<tr><td>digibank Alerts - You've received a transfer <br /> Problems viewing this email?</td></tr>
<tr><td><p>Transaction Ref: IPS0000000000000000000C100000000000<br /><br />Dear Customer,<br>
You have received SGD 1.00 via PayNow on 15 Sep 2026 14:31  SGT. <br /><br />
<strong> From:</strong>\u202fTAN AH KOW<br>
<strong>To:</strong>\u202fYour DBS/ POSB account ending 1234<br /><br />
Didn\u2019t expect these funds? Please call our DBS hotline.<br />Thank you for banking with us.</p></td></tr></table></body></html>`;
  const text = stripHtml(html);
  assert.ok(!text.includes("Transactional Alerts"), "commented-out text is not part of the message");
  assert.ok(!text.includes("&zwnj;"));
  const hit = parseBankEmail("ibanking.alert@dbs.com", text, "digibank Alerts - You've received a transfer");
  assert.ok(hit);
  assert.equal(hit.kind, "incoming");
  assert.equal(hit.amount, 1);
  assert.equal(hit.payerName, "TAN AH KOW");
  assert.equal(hit.reference, "IPS0000000000000000000C100000000000");
});

test("a figure hidden in an HTML comment is not read", () => {
  const text = stripHtml("<p>Hello</p><!-- You have received SGD 999.00 via PayNow -->");
  assert.equal(parseBankEmail("notify@dbs.com", text)?.amount, null);
});

test("bankDomainsFor gives the sender's bank, or nothing", () => {
  assert.deepEqual(bankDomainsFor("ibanking.alert@dbs.com"), ["dbs.com", "dbs.com.sg", "posb.com.sg"]);
  assert.deepEqual(bankDomainsFor("someone@example.com"), []);
  assert.deepEqual(bankDomainsFor("dbs.com@evil.example"), []);
});
