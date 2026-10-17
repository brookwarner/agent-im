import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { getCookie } from 'hono/cookie'
import { bodyLimit } from 'hono/body-limit'
import type { Env } from './types.js'
import api from './routes/api.js'
import mcp from './routes/mcp.js'
import web, { COOKIE_NAME } from './routes/web.js'
import oauth from './routes/oauth.js'
import { authenticate, equal, hash } from './lib/security.js'
import { dispatch } from './services/events.js'

const app = new Hono<{ Bindings: Env; Variables: { principal: string } }>()
app.use(
  '*',
  bodyLimit({ maxSize: 64 * 1024, onError: (c) => c.json({ error: 'Request too large' }, 413) }),
)
app.use(
  '/mcp',
  cors({
    origin: '*',
    allowHeaders: ['Authorization', 'Content-Type', 'MCP-Protocol-Version', 'Mcp-Session-Id'],
    exposeHeaders: ['WWW-Authenticate'],
  }),
)
app.use('*', async (c, next) => {
  c.header('X-Content-Type-Options', 'nosniff')
  // Keep Origin on same-origin form POSTs; no-referrer makes it null in browsers.
  // Cross-origin navigations still receive no Referer.
  c.header('Referrer-Policy', 'same-origin')
  c.header('Cache-Control', 'no-store')
  const origin = c.req.header('Origin')
  // Prevent cross-site cookie-authorised writes, including login CSRF.
  if (
    c.req.method !== 'GET' &&
    c.req.path !== '/mcp' &&
    origin &&
    origin !== new URL(c.req.url).origin
  )
    return c.json({ error: 'Origin not permitted' }, 403)
  await next()
})
app.use('/oauth/*', async (c, next) => {
  if (c.req.method === 'POST') {
    const window = Math.floor(Date.now() / 60_000)
    const key = hash(c.req.header('CF-Connecting-IP') || 'local')
    const row = await c.env.DB.prepare(
      'INSERT INTO auth_rate_limits(key,window,hits) VALUES (?,?,1) ON CONFLICT(key,window) DO UPDATE SET hits=hits+1 RETURNING hits',
    )
      .bind(key, window)
      .first<{ hits: number }>()
    if (row && row.hits > 30) {
      c.header('Retry-After', '60')
      return c.json({ error: 'rate_limited' }, 429)
    }
  }
  await next()
})
app.route('/', oauth)
app.use('*', async (c, next) => {
  const path = c.req.path
  if (path === '/' || path === '/api/status' || path === '/chat' || path.startsWith('/chat/'))
    return next()
  if (!c.env.AIM_TOKEN || !c.env.AIM_IDENTITIES || !c.env.EVENT_SECRET_KEY)
    return c.json({ error: 'Service is not configured' }, 503)
  const bearer = c.req.header('Authorization')?.match(/^Bearer (.+)$/i)?.[1]
  const cookie = getCookie(c, COOKIE_NAME)
  const principal = bearer
    ? await authenticate(c.env, bearer)
    : cookie && equal(cookie, c.env.AIM_TOKEN)
      ? 'admin'
      : null
  if (!principal) {
    c.header(
      'WWW-Authenticate',
      `Bearer resource_metadata="${new URL(c.req.url).origin}/.well-known/oauth-protected-resource"`,
    )
    return c.json({ error: 'Authorisation required' }, 401)
  }
  if (path.startsWith('/api/') && principal !== 'admin')
    return c.json({ error: 'Use MCP with your Dot identity' }, 403)
  c.set('principal', principal)
  await next()
  if (path.startsWith('/api/') && c.req.method === 'POST' && c.res.ok)
    c.executionCtx.waitUntil(dispatch(c.env, new URL(c.req.url).origin))
})
app.route('/api', api)
app.route('/mcp', mcp)
app.route('/', web)
app.notFound((c) => c.json({ error: 'Not found' }, 404))
app.onError((error, c) => {
  console.error(JSON.stringify({ event: 'request_error', message: error.message }))
  return c.json({ error: 'Internal server error' }, 500)
})
export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(dispatch(env, env.PUBLIC_URL))
    ctx.waitUntil(
      env.DB.batch([
        env.DB.prepare('DELETE FROM oauth_requests WHERE expires_at < ?').bind(Date.now()),
        env.DB.prepare('DELETE FROM oauth_codes WHERE expires_at < ?').bind(Date.now()),
        env.DB.prepare('DELETE FROM oauth_tokens WHERE expires_at < ?').bind(Date.now()),
        env.DB.prepare('DELETE FROM auth_rate_limits WHERE window < ?').bind(
          Math.floor(Date.now() / 60_000) - 2,
        ),
        env.DB.prepare(
          "DELETE FROM event_deliveries WHERE status IN ('delivered','failed','cancelled') AND created_at < ?",
        ).bind(Date.now() - 7 * 86400_000),
      ]),
    )
  },
}
export { app }
