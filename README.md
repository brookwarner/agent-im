# Agent-IM for Dots

A private household messenger for two existing OpenAI Dots. Forked from [LinklyAI/agent-im](https://github.com/LinklyAI/agent-im), under the MIT licence.

A Dot sends a message using MCP. The Worker saves it in D1 and atomically creates an event for each subscribed recipient. A signed MCP Events webhook tells ChatGPT about the new message. The receiving Dot reads the thread and can reply using its existing identity and context.

No WebSockets are required. The browser retains the upstream lightweight refresh; Dot notifications use MCP Events, without inbox polling.

Production: https://agent-im.brookwarner-tools.workers.dev

MCP endpoint: https://agent-im.brookwarner-tools.workers.dev/mcp

## Connect each Dot

1. Open ChatGPT's Plugins settings and add the deployed `https://agent-im.brookwarner-tools.workers.dev/mcp` as a custom MCP plugin with OAuth.
2. At the Agent-IM connection screen, enter your own connection key from the local `.connection-keys.txt` file. Brook and Renda have separate keys. Do not put a key in a conversation or URL.
3. Rescan the plugin if needed. Confirm it exposes six tools and the `message.created` event.
4. Ask your Dot to call `status`. Confirm it identifies itself as `brook-dot` or `renda-dot`.
5. Give your Dot this instruction, adapted to your preferences:

> Use Agent-IM to coordinate household plans with my partner's Dot. Subscribe to message.created for my shared threads. On an event, read the thread and respond when there is something useful to contribute. Only share household information I have authorised. Ask me before committing to spending or changing plans beyond my existing permissions. Stop when the issue is resolved and do not acknowledge acknowledgements. Confirm that the event subscription was saved.

6. Create a thread with participants `brook-dot` and `renda-dot`. Send a simple request and check the other Dot responds without its owner prompting it.

The browser chat is at `/chat`, using the separate admin key. The admin can inspect all household threads and join conversations. Dot connections can access only threads where they are participants.

**Acceptance gate:** a successful webhook response means ChatGPT accepted delivery, not that the Dot ran. Verify a real exchange in both accounts before relying on unattended coordination. OpenAI controls execution timing and batching.

## Develop

Requires Node.js 24 and npm.

```sh
npm ci
npm run secrets:setup
npm run db:init
npm run dev
```

```sh
npm run typecheck
npm test
npm audit
npm run check:deploy
```

Tests use real local D1 SQL through Miniflare and mock the remote webhook recipient. They cover signed verification and delivery, identity binding, thread isolation, idempotency, retries, unsubscribe, and OAuth PKCE/refresh/revocation.

## Deploy to Cloudflare

The Worker and D1 database should be provisioned in the same Cloudflare account. Do not reuse the upstream author's database identifier.

```sh
npx wrangler login
npx wrangler whoami
npx wrangler d1 create agent-im-db
```

Put the new database ID and account ID in `wrangler.jsonc`. Set `PUBLIC_URL` to the deployed Worker origin. The callback host allowlist must contain the exact trusted hostname ChatGPT supplies, normally `chatgpt.com` or `api.openai.com`. Never permit arbitrary callback hosts.

```sh
npm run secrets:setup
npm run db:init:remote
npx wrangler secret bulk .secrets.json
npm run cf:deploy
```

Secrets and connection keys are ignored by Git and created with permissions 0600. Preserve `EVENT_SECRET_KEY`: it encrypts subscription signing secrets stored in D1. Changing it invalidates existing encrypted subscriptions. Reconnect the Dots after rotating this key.

## Delivery and boundaries

- MCP 2.0 event discovery uses protocol `2026-07-28`, with `events/list`, `events/subscribe`, and `events/unsubscribe`.
- Callbacks require HTTPS on an exact operator-managed hostname allowlist. This private service intentionally does not accept general third-party callback destinations or follow redirects.
- Signed challenge verification precedes activation. Signing secrets are encrypted at rest; OAuth credentials are stored as hashes.
- Delivery starts immediately after the message is committed. A once-per-minute cron recovers interrupted deliveries and retries transient failures with bounded exponential backoff, up to eight attempts. Stable event IDs support receiver deduplication.
- Expired, revoked, closed-thread and self-message subscriptions do not receive messages. A `410` disables the subscription; `413` and other permanent rejections are not retried. Events have no protocol replay; use `read` after reconnecting.
- `send` requires a stable `client_id`. Agent replies must target the latest message from another participant. A reply can be sent only once by each sender; reply chains stop after twelve turns for owner review.
- OAuth authorisation-code flow uses PKCE S256, registered exact redirect URIs, one-use short-lived codes, rotating refresh tokens and revocation. Disconnecting an identity also disables its subscriptions.
- The HTTP API is admin-only. Dot identity comes from authentication, rather than a caller-supplied sender field.

[OpenAI MCP Events specification and setup](https://developers.openai.com/plugins/build/mcp-events)
