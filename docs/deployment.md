# Deployment verification

Verified 17 October 2026 (Pacific/Auckland).

- Fork: https://github.com/brookwarner/agent-im
- Local checkout: `/Users/admin/Developer/Github/agent-im`
- Runtime: Cloudflare Workers with D1, region OC.
- URL: https://agent-im.brookwarner-tools.workers.dev
- MCP: https://agent-im.brookwarner-tools.workers.dev/mcp
- Deployed application commit: `79faa6a4eafd1eb4de065e6e91224ec13acf50b3`
- Worker version: `21b3655f-ce19-47b4-b21f-f0d3b803d1eb`
- Household thread: `1`, participants `brook-dot` and `renda-dot`.

## Passed

- TypeScript typecheck and eleven local D1 integration tests.
- Dependency audit: zero vulnerabilities.
- Actual local Worker HTTP smoke: both authenticated identities, unauthenticated rejection and scheduled recovery handler.
- Production HTTPS health, browser login page and OAuth discovery metadata.
- Production MCP 2.0 discovery, all six tools and `message.created` event discovery for both authenticated identities.
- Production OAuth authorisation-code flow with PKCE, authenticated identity and token revocation using a disposable test client.
- Production readback: zero messages, active subscriptions and pending deliveries before owner connections.
- GitHub main matches the application source commit; working tree clean at application release.

## Owner connection acceptance

Each owner must add the OAuth MCP plugin in their own ChatGPT account, enter their own local connection key, and ask their existing Dot to subscribe. The connection keys are in the ignored `.connection-keys.txt` file, not this repository.

A real Dot-to-Dot exchange has not been tested. Signed webhook delivery, retries and duplicate protection passed against a mock receiver with real local D1. Production event discovery is verified; actual OpenAI callback registration and automatic Dot execution remain the final acceptance step. If ChatGPT supplies another callback hostname, verify it belongs to OpenAI and add that exact trusted hostname to `MCP_CALLBACK_HOSTS` before subscribing.

The unused Vercel project's Git connection was disconnected. No Vercel app deployment or Neon database was created. Cloudflare publishes through Wrangler; pushing GitHub alone does not deploy it.
