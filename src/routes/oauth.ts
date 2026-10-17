import { Hono } from 'hono'
import { randomUUID, createHash } from 'node:crypto'
import type { Env } from '../types.js'
import { hash, identityForToken, activeIdentity, equal } from '../lib/security.js'

const oauth = new Hono<{ Bindings: Env }>()
const validRedirect = (raw: string) => {
  try {
    const u = new URL(raw)
    return u.protocol === 'https:' && !u.username && !u.password && !u.hash
  } catch {
    return false
  }
}
oauth.get('/.well-known/oauth-protected-resource', (c) => {
  const origin = new URL(c.req.url).origin
  return c.json({
    resource: origin + '/mcp',
    authorization_servers: [origin],
    scopes_supported: ['household'],
  })
})
oauth.get('/.well-known/oauth-protected-resource/mcp', (c) =>
  c.redirect('/.well-known/oauth-protected-resource'),
)
oauth.get('/.well-known/oauth-authorization-server', (c) => {
  const origin = new URL(c.req.url).origin
  return c.json({
    issuer: origin,
    authorization_endpoint: origin + '/oauth/authorize',
    token_endpoint: origin + '/oauth/token',
    registration_endpoint: origin + '/oauth/register',
    revocation_endpoint: origin + '/oauth/revoke',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: ['household'],
  })
})
oauth.post('/oauth/register', async (c) => {
  const body = await c.req.json<{ redirect_uris?: string[] }>()
  if (
    !Array.isArray(body.redirect_uris) ||
    body.redirect_uris.length < 1 ||
    body.redirect_uris.length > 5 ||
    !body.redirect_uris.every(validRedirect)
  )
    return c.json({ error: 'invalid_redirect_uri' }, 400)
  const id = randomUUID()
  await c.env.DB.prepare('INSERT INTO oauth_clients(id,redirect_uris) VALUES (?,?)')
    .bind(id, JSON.stringify(body.redirect_uris))
    .run()
  return c.json(
    {
      client_id: id,
      redirect_uris: body.redirect_uris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    },
    201,
  )
})
oauth.get('/oauth/authorize', async (c) => {
  const q = c.req.query()
  const client = await c.env.DB.prepare('SELECT redirect_uris FROM oauth_clients WHERE id=?')
    .bind(q.client_id || '')
    .first<{ redirect_uris: string }>()
  if (
    !client ||
    !JSON.parse(client.redirect_uris).includes(q.redirect_uri) ||
    q.response_type !== 'code' ||
    q.code_challenge_method !== 'S256' ||
    !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge || '') ||
    (q.resource && q.resource !== new URL(c.req.url).origin + '/mcp') ||
    (q.scope && q.scope !== 'household')
  )
    return c.text('Invalid authorisation request', 400)
  const id = randomUUID()
  await c.env.DB.prepare('INSERT INTO oauth_requests(id,params,expires_at) VALUES (?,?,?)')
    .bind(id, JSON.stringify(q), Date.now() + 1800_000)
    .run()
  c.header('Cache-Control', 'no-store')
  // Chromium checks form-action again on redirects after the form POST.
  // Permit only this registered client's callback origin, in addition to ourselves.
  const callbackOrigin = new URL(q.redirect_uri).origin
  c.header(
    'Content-Security-Policy',
    `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${callbackOrigin}; frame-ancestors 'none'`,
  )
  return c.html(
    `<!doctype html><html lang="en"><meta name="viewport" content="width=device-width"><title>Connect Agent-IM</title><body style="font:18px system-ui;max-width:480px;margin:12vh auto;padding:24px"><h1>Connect your Dot</h1><p>Enter your personal Agent-IM connection key. This grants your Dot access to shared household threads under its own identity.</p><form method="post" action="/oauth/authorize"><input type="hidden" name="request" value="${id}"><label>Connection key <input type="password" name="key" required autocomplete="off" style="display:block;width:100%;margin:16px 0;padding:12px;box-sizing:border-box"></label><button style="padding:12px 24px">Connect</button></form></body></html>`,
  )
})
oauth.post('/oauth/authorize', async (c) => {
  const body = await c.req.parseBody()
  const principal = identityForToken(c.env, String(body.key || ''))
  if (!principal || principal === 'admin')
    return c.text('Use your Dot connection key, not the admin key.', 403)
  const request = await c.env.DB.prepare(
    'DELETE FROM oauth_requests WHERE id=? AND expires_at>? RETURNING params',
  )
    .bind(String(body.request || ''), Date.now())
    .first<{ params: string }>()
  if (!request)
    return c.text(
      'This connection request has expired or was already submitted. Return to ChatGPT and start a new connection; refreshing this page resubmits the old form.',
      400,
    )
  const q = JSON.parse(request.params)
  const code = randomUUID() + randomUUID()
  await c.env.DB.prepare(
    'INSERT INTO oauth_codes(code_hash,principal,client_id,redirect_uri,challenge,expires_at) VALUES (?,?,?,?,?,?)',
  )
    .bind(
      hash(code),
      principal,
      q.client_id,
      q.redirect_uri,
      q.code_challenge,
      Date.now() + 300_000,
    )
    .run()
  const url = new URL(q.redirect_uri)
  url.searchParams.set('code', code)
  if (q.state) url.searchParams.set('state', q.state)
  c.header('Cache-Control', 'no-store')
  c.header('Referrer-Policy', 'no-referrer')
  return c.redirect(url.toString(), 303)
})
oauth.post('/oauth/token', async (c) => {
  const b = await c.req.parseBody()
  let principal: string
  let family: string
  if (b.resource && b.resource !== new URL(c.req.url).origin + '/mcp')
    return c.json({ error: 'invalid_target' }, 400)
  if (b.grant_type === 'authorization_code') {
    const code = await c.env.DB.prepare(
      'SELECT * FROM oauth_codes WHERE code_hash=? AND expires_at>?',
    )
      .bind(hash(String(b.code || '')), Date.now())
      .first<{ principal: string; client_id: string; redirect_uri: string; challenge: string }>()
    const verifier = String(b.code_verifier || '')
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    if (
      !code ||
      !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
      code.client_id !== b.client_id ||
      code.redirect_uri !== b.redirect_uri ||
      !equal(code.challenge, challenge)
    )
      return c.json({ error: 'invalid_grant' }, 400)
    const used = await c.env.DB.prepare(
      'DELETE FROM oauth_codes WHERE code_hash=? RETURNING principal',
    )
      .bind(hash(String(b.code)))
      .first()
    if (!used) return c.json({ error: 'invalid_grant' }, 400)
    principal = code.principal
    family = randomUUID()
  } else if (b.grant_type === 'refresh_token') {
    const token = await c.env.DB.prepare(
      "DELETE FROM oauth_tokens WHERE token_hash=? AND kind='refresh' AND client_id=? AND expires_at>? RETURNING principal,family",
    )
      .bind(hash(String(b.refresh_token || '')), String(b.client_id || ''), Date.now())
      .first<{ principal: string; family: string }>()
    if (!token) return c.json({ error: 'invalid_grant' }, 400)
    principal = token.principal
    family = token.family
    await c.env.DB.prepare('DELETE FROM oauth_tokens WHERE family=?').bind(family).run()
  } else return c.json({ error: 'unsupported_grant_type' }, 400)
  if (!activeIdentity(c.env, principal)) return c.json({ error: 'invalid_grant' }, 400)
  const access = randomUUID() + randomUUID(),
    refresh = randomUUID() + randomUUID()
  await c.env.DB.batch([
    c.env.DB.prepare('INSERT INTO oauth_tokens VALUES (?,?,?,?,?,?)').bind(
      hash(access),
      principal,
      String(b.client_id),
      'access',
      Date.now() + 3600_000,
      family,
    ),
    c.env.DB.prepare('INSERT INTO oauth_tokens VALUES (?,?,?,?,?,?)').bind(
      hash(refresh),
      principal,
      String(b.client_id),
      'refresh',
      Date.now() + 30 * 86400_000,
      family,
    ),
  ])
  c.header('Cache-Control', 'no-store')
  c.header('Pragma', 'no-cache')
  return c.json({
    access_token: access,
    refresh_token: refresh,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'household',
  })
})
oauth.post('/oauth/revoke', async (c) => {
  const b = await c.req.parseBody()
  const token = await c.env.DB.prepare(
    'SELECT family FROM oauth_tokens WHERE token_hash=? AND client_id=?',
  )
    .bind(hash(String(b.token || '')), String(b.client_id || ''))
    .first<{ family: string }>()
  if (token) {
    // Disconnecting this Dot also stops its event subscriptions.
    const owner = await c.env.DB.prepare(
      'SELECT principal FROM oauth_tokens WHERE family=? LIMIT 1',
    )
      .bind(token.family)
      .first<{ principal: string }>()
    await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM oauth_tokens WHERE family=?').bind(token.family),
      c.env.DB.prepare('UPDATE event_subscriptions SET active=0 WHERE principal=?').bind(
        owner?.principal || '',
      ),
    ])
  }
  return c.body(null, 200)
})
export default oauth
