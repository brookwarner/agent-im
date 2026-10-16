# Agent-IM for Dots

Private household messenger forked from LinklyAI/agent-im. Deployment target is Cloudflare Workers and D1. See README.md for connection, development and deployment steps.

## Rules

- Preserve the upstream MIT licence.
- No WebSockets: the main use case uses signed MCP Events webhooks.
- Keep all secrets, local keys, credentials and private conversations out of Git. `.secrets.json`, `.connection-keys.txt` and `.dev.vars` are private ignored files.
- Each Dot has its own authenticated principal. Never permit caller-supplied sender identity or allow agents to read threads they do not participate in.
- Message and outbox creation must remain atomic. A webhook 2xx is delivery acceptance, not proof of a Dot response.
- Never expand the callback hostname allowlist to arbitrary hosts. Keep redirects disabled.
- Keep reply idempotency, self-event suppression, twelve-turn limit and bounded retries.
- Run typecheck, integration tests and deployment dry-run before publishing.

## Structure

- `src/index.ts`: HTTP app, authentication and scheduled outbox recovery.
- `src/routes/mcp.ts`: tools and MCP event discovery/subscription methods.
- `src/routes/oauth.ts`: OAuth PKCE connection, refresh and revoke.
- `src/services/im.ts`: shared message/thread services.
- `src/services/events.ts`: callback validation, verification, encryption and delivery.
- `src/db/schema.sql`, `src/db/events.sql`: additive schema and atomic outbox trigger.
- `tests/messaging.test.ts`: local D1 integration coverage.
