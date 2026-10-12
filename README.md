<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
    <img src="assets/logo-light.png" alt="ConfirmPay logo" width="300">
  </picture>
</p>

<h1 align="center">Email reader</h1>

<p align="center">
  The code that reads the bank emails an organisation forwards to ConfirmPay.
</p>

<p align="center">
  <a href="https://confirmpay.link"><b>Website</b></a> ·
  <a href="#what-it-does"><b>What it does</b></a> ·
  <a href="#what-leaves-the-worker"><b>What leaves the Worker</b></a> ·
  <a href="LICENSE"><b>MIT Licence</b></a>
</p>

<br>

This Worker is the only part of [ConfirmPay](https://confirmpay.link) that ever holds the raw email, and it is small enough to read in one sitting: about 500 lines of TypeScript, no AI, no database.

The rest of ConfirmPay (the website, the API and the database) is not published. [What is not here](#what-is-not-here) says where that line falls.

## What it does

An organisation sets one filter in its own inbox that forwards its bank's notices to a private address, `<token>@confirmpay.link`. Cloudflare Email Routing hands each email to this Worker, which:

1. **Checks the address.** The part before the `@` must be 16 to 40 hex characters, like a ConfirmPay token. Anything else is dropped.
2. **Turns the email into text.** It uses [postal-mime](https://github.com/postalsys/postal-mime), and strips tags and entities from an HTML-only email (`stripHtml` in `src/parsers.ts`).
3. **Handles Gmail's "confirm forwarding" email.** If it is that email, the Worker sends only the confirm link, the token and the provider's name to ConfirmPay, so the organisation can click it, and stops.
4. **Reads the payment.** For a known bank's sender address it picks out the amount, the reference and the payer's name with plain regular expressions (`src/parsers.ts`), and decides whether the email says money came in, went out, or neither. Same email in, same answer out.
5. **Checks that the email really came from the bank.** It reads the verdict Cloudflare's mail servers wrote into the headers (`src/auth.ts`). Only the newest authentication header counts, and only if it names `mx.cloudflare.net`, so a header pasted into the email by a forger counts for nothing.
6. **Sends the result to ConfirmPay** (`src/index.ts`), retrying if ConfirmPay cannot be reached, because a bank email has no second delivery.

The parsers for DBS, UOB and OCBC were written from real notifications. The others (Standard Chartered, Maybank, HSBC, Citi, CIMB, Trust, GXS) are best effort. A miss leaves the field empty and the organisation confirms by hand. It never produces a wrong match.

## What leaves the Worker

This is the whole message the Worker sends for a bank email (`payload` in `src/index.ts`):

| Field | What it is |
| --- | --- |
| `token` | The token from the private address the email was sent to (the part before the `@`) |
| `sender` | The address the email says it is from |
| `messageId` | The email's own ID, so one email is never counted twice |
| `amount` | The amount, or `null` |
| `reference` | The reference, or `null` |
| `payerName` | The payer's name as the bank printed it (80 characters at most), or `null` |
| `kind` | `incoming`, `outgoing` or `other` |
| `auth.verdict` | `verified`, `unverified` or `unknown` |
| `auth.summary` | One line (900 characters at most): why that verdict, how many ARC seals and which domains signed the email, and the newest authentication header as Cloudflare wrote it. It is header text, not message text |

Not sent, anywhere: the body, the HTML, the subject, attachments, the To and Cc lines, and every header other than the sender, the message ID and that one authentication header.

Two things you can check for yourself:

```
grep -n "fetch(" src/*.ts      # two network calls, both to ConfirmPay (INTAKE_URL and FORWARDING_CONFIRM_URL)
grep -n "console\." src/*.ts   # every log line: the token, a status code, the kind and the verdict
                               # (an email that is dropped logs the address it was sent to)
```

`wrangler.toml` has no storage bindings (no KV, D1, R2 or queues), so the Worker keeps nothing between emails.

## Run the tests

You need Node 22.18 or newer, which runs the TypeScript tests directly.

```
npm install
npm test
npm run typecheck
```

The sample emails in `test/` are made up. Names, account digits, references, addresses and links are placeholders.

## What is not here

The website, the API, the database, sign-in and the dashboard are private. That includes the part that receives the fields above, finds the waiting payment request they belong to, marks it paid and keeps a record of what was read. [The privacy policy](https://confirmpay.link/privacy) describes that record, but its code is not published, so you cannot check it here.

This repository is a copy of the Worker's folder in ConfirmPay's private repository, and it is updated whenever the Worker changes. You can read it, run it and test it. You cannot inspect the deployed build itself, so that the two match is the maintainer's word.

## Licence

MIT, see [LICENSE](LICENSE). That covers this repository only; the rest of ConfirmPay is not part of it.

## Questions

Open an issue here for anything about the code. To ask about your data, or to have it deleted, use [confirmpay.link/delete-data](https://confirmpay.link/delete-data).
