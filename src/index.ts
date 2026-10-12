import PostalMime from "postal-mime";
import { parseBankEmail, isTrustedSender, detectForwardingConfirmation, stripHtml, bankDomainsFor } from "./parsers";
import { judgeAuth, type AuthResult, type Header } from "./auth";

export interface Env {
  /** URL of the confirmation-intake Pages Function, e.g. https://confirmpay.link/api/intake */
  INTAKE_URL: string;
  /** URL of the forwarding-confirm relay Pages Function (same origin as INTAKE_URL). */
  FORWARDING_CONFIRM_URL: string;
  /** Shared secret; must match the Pages project's INTAKE_SECRET. */
  INTAKE_SECRET: string;
}

/** inbound_token is randomToken(10) => 20 lowercase hex chars; allow a range. */
const TOKEN_RE = /^[0-9a-f]{16,40}$/i;

/**
 * POSTs to the intake, retrying when it can't be reached or answers with a server error. A bank
 * email is the only signal that a payment arrived and has no second delivery, so a network blip
 * or a deploy in progress must not mean a payment that never confirms. Safe to repeat: intake
 * records each message id first, so a repeat does nothing.
 */
async function postWithRetry(url: string, init: RequestInit, attempts = 3): Promise<Response> {
  let failure: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, init);
      if (res.status < 500) return res;
      failure = new Error(`HTTP ${res.status}`);
    } catch (err) {
      failure = err;
    }
    if (i < attempts - 1) await new Promise((r) => setTimeout(r, 400 * 2 ** i));
  }
  throw failure;
}

export default {
  /**
   * Triggered by Email Routing when a forwarded bank notification arrives at
   * {token}@confirmpay.link. Never writes to Supabase: it extracts and hands off to intake, so
   * all matching logic stays in one place.
   */
  async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
    const recipient = (message.to || "").toLowerCase();
    const localPart = recipient.split("@")[0]?.trim() ?? "";

    if (!TOKEN_RE.test(localPart)) {
      console.log(`drop: recipient is not a token address (${recipient})`);
      return;
    }

    let sender = (message.from || "").toLowerCase();
    let body = "";
    let subject = "";
    // Top-most first, as the message carries them; the authentication check
    // depends on that order.
    let headers: Header[] = [];
    let messageId = message.headers.get("message-id") || "";

    try {
      const parsed = await PostalMime.parse(message.raw);
      sender = (parsed.from?.address || sender).toLowerCase();
      messageId = parsed.messageId || messageId;
      body = parsed.text || (parsed.html ? stripHtml(parsed.html) : "");
      subject = parsed.subject ?? "";
      headers = parsed.headers.map((h) => ({ key: h.key, value: h.value }));
    } catch (err) {
      console.log(`parse error for ${localPart}: ${(err as Error).message}`);
    }

    if (!messageId) messageId = `synth-${localPart}-${Date.now()}`;

    const forwardingHit = detectForwardingConfirmation(sender, body);
    if (forwardingHit) {
      try {
        const res = await fetch(env.FORWARDING_CONFIRM_URL, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-intake-secret": env.INTAKE_SECRET,
          },
          body: JSON.stringify({
            token: localPart,
            confirmUrl: forwardingHit.confirmUrl,
            provider: forwardingHit.provider,
          }),
        });
        console.log(`forwarding-confirm ${res.status} token=${localPart} provider=${forwardingHit.provider}`);
      } catch (err) {
        console.log(`forwarding-confirm call failed for ${localPart}: ${(err as Error).message}`);
      }
      return;
    }

    const hit = parseBankEmail(sender, body, subject);
    // Only worth judging for a bank we know; anything else can't match anyway.
    const auth: AuthResult = hit
      ? judgeAuth(headers, sender, bankDomainsFor(sender))
      : { verdict: "unknown", summary: "sender is not a known bank" };
    const payload = {
      token: localPart,
      sender,
      messageId,
      amount: hit?.amount ?? null,
      reference: hit?.reference ?? null,
      payerName: hit?.payerName ?? null,
      kind: hit?.kind ?? "other",
      auth,
    };

    try {
      const res = await postWithRetry(env.INTAKE_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-intake-secret": env.INTAKE_SECRET,
        },
        body: JSON.stringify(payload),
      });
      console.log(
        `intake ${res.status} token=${localPart} trusted=${isTrustedSender(sender)} kind=${payload.kind} auth=${auth.verdict} ` +
          `matched=${payload.reference ? "ref" : payload.amount ? "amt" : "none"}`,
      );
    } catch (err) {
      // Nothing to bounce to — the org's forwarding rule is fire-and-forget.
      // The email is still visible in the org's own inbox regardless.
      console.log(`intake call failed for ${localPart}: ${(err as Error).message}`);
    }
  },
};
