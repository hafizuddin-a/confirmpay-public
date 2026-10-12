/**
 * Authentication verdicts. The lower ARC set is copied from a real DBS notification as Gmail
 * delivered it (DKIM from dbs.com and amazonses.com, SPF for amazonses.com, DMARC pass for
 * dbs.com). The set Cloudflare adds on top is written from its documentation, not a captured
 * message: when a real forwarded one arrives, add it here verbatim.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { judgeAuth, type Header } from "../src/auth.ts";

const DBS = ["dbs.com", "posb.com.sg"];
const FROM = "ibanking.alert@dbs.com";

const GOOGLE_SET: Header[] = [
  { key: "arc-seal", value: "i=1; a=rsa-sha256; t=1789453865; cv=none; d=google.com; s=arc-20260327; b=aAZj" },
  { key: "arc-message-signature", value: "i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20260327; h=feedback-id:mime-version" },
  {
    key: "arc-authentication-results",
    value:
      "i=1; mx.google.com;\n       dkim=pass header.i=@dbs.com header.s=xknyn7yskizb2b7esz5fe7bkhydjdctx header.b=mkaPbb3u;\n" +
      "       dkim=pass header.i=@amazonses.com header.s=224i4yxa5dv7c2xz3womw6peuasteono header.b=WDTiwpW2;\n" +
      "       spf=pass (google.com: domain of 0100@amazonses.com designates 54.240.10.176 as permitted sender) smtp.mailfrom=0100@amazonses.com;\n" +
      "       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=dbs.com",
  },
];

const DKIM: Header[] = [
  { key: "dkim-signature", value: "v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple; s=xknyn7yskizb2b7esz5fe7bkhydjdctx; d=dbs.com; t=1789453865;" },
  { key: "dkim-signature", value: "v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple; s=224i4yxa5dv7c2xz3womw6peuasteono; d=amazonses.com; t=1789453865;" },
];

/** What Cloudflare puts on top: its own seal and verdict, one instance higher. */
const cloudflare = (verdict: string, instance = 2): Header[] => [
  { key: "arc-seal", value: `i=${instance}; a=rsa-sha256; s=cf2024-1; d=confirmpay.link; cv=pass; b=xyz` },
  { key: "arc-message-signature", value: `i=${instance}; a=rsa-sha256; s=cf2024-1; d=confirmpay.link; b=xyz` },
  { key: "arc-authentication-results", value: `i=${instance}; mx.cloudflare.net; ${verdict}` },
];

const GOOD =
  "dkim=pass header.d=dbs.com header.s=xknyn7yskizb2b7esz5fe7bkhydjdctx; " +
  "dmarc=pass header.from=dbs.com policy.dmarc=quarantine; spf=fail smtp.mailfrom=gmail.com; arc=pass";

const judge = (headers: Header[], from = FROM) => judgeAuth(headers, from, DBS);

test("a forwarded bank email that Cloudflare saw pass DMARC for the bank is verified", () => {
  const r = judge([...cloudflare(GOOD), ...GOOGLE_SET, ...DKIM]);
  assert.equal(r.verdict, "verified");
  assert.match(r.summary, /dmarc=pass for dbs\.com/);
  assert.match(r.summary, /dkim-signatures=dbs\.com,amazonses\.com/);
  assert.match(r.summary, /arc-seals=2/);
});

test("it does not matter that SPF failed, as it always does for a forwarded message", () => {
  assert.equal(judge([...cloudflare(GOOD), ...GOOGLE_SET, ...DKIM]).verdict, "verified");
});

test("DMARC failing or missing means unverified", () => {
  for (const verdict of [
    "dkim=pass header.d=evil.example; dmarc=fail header.from=dbs.com policy.dmarc=quarantine; spf=pass",
    "dmarc=none header.from=dbs.com",
    "dmarc=temperror header.from=dbs.com",
    "dkim=pass header.d=dbs.com; spf=pass",
  ]) {
    assert.equal(judge([...cloudflare(verdict), ...DKIM]).verdict, "unverified", verdict);
  }
});

test("DMARC passing for some other domain does not make a bank email verified", () => {
  // The sender signed as themselves, then wrote a bank's address in From.
  const evil = "dkim=pass header.d=evil.example; dmarc=pass header.from=evil.example; spf=pass";
  const r = judge([...cloudflare(evil), ...DKIM], "ibanking.alert@dbs.com");
  assert.equal(r.verdict, "unverified");
  assert.match(r.summary, /evil\.example/);
  // and the same email honestly from that domain is not a bank either
  assert.equal(judge([...cloudflare(evil)], "pay@evil.example").verdict, "unverified");
});

test("look-alike domains are not the bank's", () => {
  for (const d of ["dbs.com.evil.example", "notdbs.com", "dbs.com.sg.example"]) {
    const v = `dmarc=pass header.from=${d}`;
    assert.equal(judge([...cloudflare(v)], `a@${d}`).verdict, "unverified", d);
  }
  // a real subdomain is fine
  assert.equal(judge([...cloudflare("dmarc=pass header.from=alerts.dbs.com")], "a@alerts.dbs.com").verdict, "verified");
});

test("the header.from DMARC passed for has to be the address the email is from", () => {
  const v = "dmarc=pass header.from=posb.com.sg";
  assert.equal(judge([...cloudflare(v)], "ibanking.alert@dbs.com").verdict, "unverified");
});

// The attack the "top-most only" rule exists for: the sender writes their own
// verdict into the message, below whatever the receiving servers add.
test("a verdict pasted into the message, with Cloudflare's own header above it, is ignored", () => {
  const forged: Header[] = [
    { key: "arc-seal", value: "i=1; a=rsa-sha256; cv=none; d=evil.example; b=x" },
    { key: "arc-authentication-results", value: `i=1; mx.cloudflare.net; ${GOOD}` },
  ];
  const real = cloudflare("dkim=pass header.d=evil.example; dmarc=fail header.from=dbs.com; spf=pass", 2);
  assert.equal(judge([...real, ...forged]).verdict, "unverified");
});

test("a pasted-in verdict with nothing of Cloudflare's above it is not trusted when its seal does not line up", () => {
  const forgedOnly: Header[] = [{ key: "arc-authentication-results", value: `i=1; mx.cloudflare.net; ${GOOD}` }];
  assert.equal(judge(forgedOnly).verdict, "unknown");
  const wrongSeal: Header[] = [
    { key: "arc-seal", value: "i=3; a=rsa-sha256; cv=none; d=evil.example; b=x" },
    { key: "arc-authentication-results", value: `i=1; mx.cloudflare.net; ${GOOD}` },
  ];
  assert.equal(judge(wrongSeal).verdict, "unknown");
});

test("a newest verdict from anyone but Cloudflare is not enough", () => {
  assert.equal(judge([...GOOGLE_SET, ...DKIM]).verdict, "unknown");
  const spoofedName: Header[] = [
    { key: "arc-seal", value: "i=1; a=rsa-sha256; cv=none; d=evil.example; b=x" },
    { key: "arc-authentication-results", value: `i=1; mx.cloudflare.net.evil.example; ${GOOD}` },
  ];
  assert.equal(judge(spoofedName).verdict, "unknown");
});

test("no authentication header at all, or one we can't read, is unknown", () => {
  assert.equal(judge([]).verdict, "unknown");
  assert.equal(judge(DKIM).verdict, "unknown");
  assert.equal(judge([{ key: "arc-authentication-results", value: "nonsense" }]).verdict, "unknown");
  assert.equal(judge([{ key: "arc-authentication-results", value: "" }]).verdict, "unknown");
});

test("a plain Authentication-Results from Cloudflare counts too, and is read the same way", () => {
  const plain: Header[] = [{ key: "authentication-results", value: `mx.cloudflare.net; ${GOOD}` }];
  assert.equal(judge(plain).verdict, "verified");
  const bad: Header[] = [{ key: "authentication-results", value: "mx.cloudflare.net; dmarc=fail header.from=dbs.com" }];
  assert.equal(judge(bad).verdict, "unverified");
});

test("values are matched without regard to case or folding, and comments are ignored", () => {
  const folded = "DKIM=PASS header.d=DBS.com;\n  DMARC=Pass (p=none sp=none dis=none) header.from=DBS.COM";
  assert.equal(judge([...cloudflare(folded)], "Ibanking.Alert@DBS.com").verdict, "verified");
});

test("the summary is short and never contains the message", () => {
  const r = judge([...cloudflare(GOOD), ...GOOGLE_SET, ...DKIM]);
  assert.ok(r.summary.length <= 900);
  const long = judge([...cloudflare("dmarc=fail header.from=dbs.com; " + "x=y; ".repeat(500))]);
  assert.ok(long.summary.length <= 900);
});
