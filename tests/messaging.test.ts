import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile, mkdir } from 'node:fs/promises'
import { randomBytes, createHash } from 'node:crypto'
import { Miniflare, convertV4MiniflareOptions } from 'miniflare'
import { build } from 'esbuild'
import { Webhook } from 'standardwebhooks'
import { subscribe, unsubscribe, dispatch, validateCallback } from '../src/services/events.js'
import { seal, unseal } from '../src/lib/security.js'
import type { Env } from '../src/types.js'

test('household messaging and MCP Events', async (t) => {
  await mkdir('.test-build', { recursive: true })
  await build({
    entryPoints: ['src/index.ts'],
    outfile: '.test-build/app.mjs',
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    loader: { '.html': 'text' },
  })
  const { app } = await import('../.test-build/app.mjs')
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default {fetch(){return new Response("ok")}}',
      d1Databases: ['DB'],
      compatibilityDate: '2026-10-12',
    }),
  )
  const db = await mf.getD1Database('DB')
  async function schema(file: string) {
    const sql = await readFile(file, 'utf8')
    const trigger = sql.indexOf('CREATE TRIGGER')
    const first = trigger < 0 ? sql : sql.slice(0, trigger)
    for (const statement of first
      .replace(/--[^\n]*/g, '')
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean))
      await db.prepare(statement).run()
    if (trigger >= 0) await db.prepare(sql.slice(trigger)).run()
  }
  await schema('src/db/schema.sql')
  await schema('src/db/events.sql')
  const env: Env = {
    DB: db as D1Database,
    AIM_TOKEN: 'admin-test-key',
    AIM_IDENTITIES: JSON.stringify({
      'brook-dot': 'brook-test-key',
      'renda-dot': 'renda-test-key',
    }),
    EVENT_SECRET_KEY: randomBytes(32).toString('base64'),
    MCP_CALLBACK_HOSTS: 'callback.example',
    PUBLIC_URL: 'https://messenger.example',
  }
  const pending: Promise<unknown>[] = []
  const ctx = {
    waitUntil: (p: Promise<unknown>) => {
      pending.push(p)
    },
    passThroughOnException() {},
    props: {},
  }
  const secret = 'whsec_' + randomBytes(32).toString('base64')
  const received: Record<string, unknown>[] = []
  const fakeFetch: typeof fetch = async (input, init) => {
    assert.equal(String(input), 'https://callback.example/inbound')
    const h = new Headers(init?.headers)
    const payload = new Webhook(secret).verify(String(init?.body), Object.fromEntries(h)) as Record<
      string,
      unknown
    >
    received.push(payload)
    return Response.json(
      payload.type === 'verification' ? { challenge: payload.challenge } : { accepted: true },
    )
  }
  const original = globalThis.fetch
  globalThis.fetch = fakeFetch
  const rpc = async (method: string, params: object = {}, key = 'brook-test-key') => {
    const r = await app.request(
      'https://messenger.example/mcp',
      {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      },
      env,
      ctx,
    )
    return { status: r.status, body: await r.json() }
  }
  let thread: number, subscriptionId: string
  try {
    await t.test('fails closed and prevents agent use of admin HTTP API', async () => {
      assert.equal((await app.request('/mcp', { method: 'POST' }, env, ctx)).status, 401)
      const r = await app.request(
        '/api/profiles',
        { headers: { Authorization: 'Bearer brook-test-key' } },
        env,
        ctx,
      )
      assert.equal(r.status, 403)
      const missing = await app.request('/mcp', { method: 'POST' }, { ...env, AIM_TOKEN: '' }, ctx)
      assert.equal(missing.status, 503)
    })
    await t.test('discovers MCP 2.0 tools, identity, and event filters', async () => {
      assert.deepEqual((await rpc('server/discover')).body.result.capabilities, {
        tools: {},
        events: {},
      })
      assert.equal((await rpc('events/list')).body.result.events[0].name, 'message.created')
      assert.equal(
        JSON.parse((await rpc('tools/call', { name: 'status' })).body.result.content[0].text)
          .identity,
        'brook-dot',
      )
    })
    await t.test('creates a shared thread and rejects identity spoofing', async () => {
      const r = await rpc('tools/call', {
        name: 'create_thread',
        arguments: { topic: 'Dinner', participants: ['brook-dot', 'renda-dot'] },
      })
      thread = JSON.parse(r.body.result.content[0].text).id
      const spoof = await rpc('tools/call', {
        name: 'send',
        arguments: {
          thread_id: String(thread),
          content: 'hello',
          client_id: 'x',
          from: 'renda-dot',
        },
      })
      assert.equal(spoof.body.error.code, -32602)
    })
    await t.test(
      'validates callbacks, verifies signatures and stores an encrypted subscription idempotently',
      async () => {
        for (const url of [
          'http://callback.example/inbound',
          'https://127.0.0.1',
          'https://callback.example.evil/inbound',
          'https://user@callback.example/inbound',
        ])
          assert.throws(() => validateCallback(env, url))
        const productionCallbacks = { ...env, MCP_CALLBACK_HOSTS: undefined }
        assert.equal(
          validateCallback(productionCallbacks, 'https://connectors.api.openai.com/inbound')
            .hostname,
          'connectors.api.openai.com',
        )
        assert.throws(() =>
          validateCallback(
            productionCallbacks,
            'https://connectors.api.openai.com.evil.example/inbound',
          ),
        )
        assert.throws(() =>
          validateCallback(productionCallbacks, 'http://connectors.api.openai.com/inbound'),
        )
        const params = {
          name: 'message.created',
          arguments: { thread_id: thread },
          delivery: { mode: 'webhook', url: 'https://callback.example/inbound', secret },
        }
        const sub = await subscribe(env, 'renda-dot', params, fakeFetch)
        subscriptionId = sub.id
        assert.equal((await subscribe(env, 'renda-dot', params, fakeFetch)).id, sub.id)
        assert.equal(received.filter((p) => p.type === 'verification').length, 1)
        const stored = await db
          .prepare('SELECT secret FROM event_subscriptions WHERE id=?')
          .bind(sub.id)
          .first<{ secret: string }>()
        assert.notEqual(stored!.secret, secret)
        assert.equal(await unseal(env, stored!.secret), secret)
        await assert.rejects(() =>
          subscribe(env, 'brook-dot', params, async () => Response.json({ challenge: 'wrong' })),
        )
      },
    )
    let messageId: string
    await t.test(
      'sends once, queues atomically, and delivers a signed event without polling',
      async () => {
        const args = {
          thread_id: String(thread),
          content: 'Are you free at seven?',
          client_id: 'dinner-1',
        }
        const sent = await rpc('tools/call', { name: 'send', arguments: args })
        assert.equal(sent.body.error, undefined)
        messageId = JSON.parse(sent.body.result.content[0].text).id
        await Promise.all(pending.splice(0))
        const events = received.filter((p) => p.name === 'message.created')
        assert.equal(events.length, 1)
        assert.equal((events[0].data as Record<string, unknown>).message_id, messageId)
        const again = await rpc('tools/call', { name: 'send', arguments: args })
        assert.equal(JSON.parse(again.body.result.content[0].text).id, messageId)
        assert.equal(
          (await db.prepare('SELECT COUNT(*) n FROM messages').first<{ n: number }>())!.n,
          1,
        )
        assert.equal(
          (await db.prepare('SELECT status FROM event_deliveries').first<{ status: string }>())!
            .status,
          'delivered',
        )
      },
    )
    await t.test(
      'recipient reads and replies; own messages never trigger its subscription',
      async () => {
        const read = await rpc(
          'tools/call',
          { name: 'read', arguments: { thread_id: String(thread) } },
          'renda-test-key',
        )
        assert.equal(JSON.parse(read.body.result.content[0].text).messages[0].id, messageId)
        const sent = await rpc(
          'tools/call',
          {
            name: 'send',
            arguments: {
              thread_id: String(thread),
              content: 'Yes, seven works.',
              reply_to: messageId,
              client_id: 'dinner-reply',
            },
          },
          'renda-test-key',
        )
        assert.equal(sent.body.error, undefined)
        await Promise.all(pending.splice(0))
        assert.equal(received.filter((p) => p.name === 'message.created').length, 1)
        const duplicate = await rpc(
          'tools/call',
          {
            name: 'send',
            arguments: {
              thread_id: String(thread),
              content: 'Another reply',
              reply_to: messageId,
              client_id: 'new-key',
            },
          },
          'renda-test-key',
        )
        assert.equal(duplicate.body.error.code, -32602)
      },
    )
    await t.test('isolates threads and subscriptions by identity', async () => {
      const result = await rpc('tools/call', {
        name: 'create_thread',
        arguments: { topic: 'Private', participants: ['brook-dot'] },
      })
      const id = JSON.parse(result.body.result.content[0].text).id
      assert.equal(
        (
          await rpc(
            'tools/call',
            { name: 'read', arguments: { thread_id: String(id) } },
            'renda-test-key',
          )
        ).body.error.message,
        'Thread not found',
      )
      await assert.rejects(() =>
        subscribe(
          env,
          'renda-dot',
          {
            name: 'message.created',
            arguments: { thread_id: id },
            delivery: { mode: 'webhook', url: 'https://callback.example/inbound', secret },
          },
          fakeFetch,
        ),
      )
    })
    await t.test(
      'transient failure retains a stable event id and retries; permanent rejection stops',
      async () => {
        await db
          .prepare("UPDATE event_deliveries SET status='pending',attempts=0,next_attempt_at=0")
          .run()
        const ids: string[] = []
        await dispatch(env, env.PUBLIC_URL, async (_i, init) => {
          ids.push(new Headers(init?.headers).get('webhook-id')!)
          return new Response('', { status: 503 })
        })
        let row = await db
          .prepare('SELECT status,attempts FROM event_deliveries')
          .first<{ status: string; attempts: number }>()
        assert.equal(row!.status, 'pending')
        assert.equal(row!.attempts, 1)
        await db.prepare('UPDATE event_deliveries SET next_attempt_at=0').run()
        await dispatch(env, env.PUBLIC_URL, async (_i, init) => {
          ids.push(new Headers(init?.headers).get('webhook-id')!)
          return new Response('', { status: 413 })
        })
        row = await db.prepare('SELECT status,attempts FROM event_deliveries').first()
        assert.equal(row!.status, 'failed')
        assert.equal(ids[0], ids[1])
      },
    )
    await t.test('unsubscribe is idempotent and stops pending delivery', async () => {
      const p = {
        name: 'message.created',
        arguments: { thread_id: thread },
        delivery: { mode: 'webhook', url: 'https://callback.example/inbound' },
      }
      await unsubscribe(env, 'renda-dot', p)
      await unsubscribe(env, 'renda-dot', p)
      const s = await db
        .prepare('SELECT active FROM event_subscriptions WHERE id=?')
        .bind(subscriptionId)
        .first<{ active: number }>()
      assert.equal(s!.active, 0)
    })
    await t.test('OAuth PKCE connection, token rotation, and revocation', async () => {
      const request = async (
        path: string,
        body: object | URLSearchParams,
        origin = 'https://messenger.example',
      ) => {
        const form = body instanceof URLSearchParams
        const r = await app.request(
          'https://messenger.example' + path,
          {
            method: 'POST',
            headers: {
              'Content-Type': form ? 'application/x-www-form-urlencoded' : 'application/json',
              Origin: origin,
            },
            body: form ? body.toString() : JSON.stringify(body),
          },
          env,
          ctx,
        )
        return r
      }
      const registered = await (
        await request('/oauth/register', {
          redirect_uris: ['https://chatgpt.com/connector/callback'],
        })
      ).json()
      const verifier = randomBytes(48).toString('base64url'),
        challenge = createHash('sha256').update(verifier).digest('base64url')
      const q = new URLSearchParams({
        client_id: registered.client_id,
        redirect_uri: 'https://chatgpt.com/connector/callback',
        response_type: 'code',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'test-state',
        scope: 'household',
      })
      const page = await app.request('https://messenger.example/oauth/authorize?' + q, {}, env, ctx)
      assert.equal(page.headers.get('Referrer-Policy'), 'same-origin')
      assert.match(
        page.headers.get('Content-Security-Policy')!,
        /form-action 'self' https:\/\/chatgpt\.com;/,
      )
      assert.doesNotMatch(page.headers.get('Content-Security-Policy')!, /form-action[^;]*\*/)
      const savedRequest = await db
        .prepare('SELECT expires_at FROM oauth_requests ORDER BY expires_at DESC LIMIT 1')
        .first<{ expires_at: number }>()
      assert.ok(savedRequest!.expires_at - Date.now() > 29 * 60_000)
      const loginPage = await app.request('https://messenger.example/chat', {}, env, ctx)
      assert.equal(loginPage.headers.get('Referrer-Policy'), 'same-origin')
      const html = await page.text()
      const id = html.match(/name="request" value="([^"]+)"/)![1]
      for (const origin of ['https://untrusted.example', 'null']) {
        const rejected = await request(
          '/oauth/authorize',
          new URLSearchParams({ request: id, key: 'brook-test-key' }),
          origin,
        )
        assert.equal(rejected.status, 403)
        assert.equal((await rejected.json()).error, 'Origin not permitted')
      }
      const auth = await request(
        '/oauth/authorize',
        new URLSearchParams({ request: id, key: 'brook-test-key' }),
      )
      assert.equal(auth.status, 303)
      const location = new URL(auth.headers.get('Location')!)
      assert.equal(location.searchParams.get('state'), 'test-state')
      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: registered.client_id,
        redirect_uri: 'https://chatgpt.com/connector/callback',
        code: location.searchParams.get('code')!,
        code_verifier: verifier,
      })
      const tokens = await (await request('/oauth/token', params)).json()
      assert.ok(tokens.access_token)
      assert.equal((await rpc('ping', {}, tokens.access_token)).status, 200)
      assert.equal((await request('/oauth/token', params)).status, 400)
      const refresh = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: registered.client_id,
        refresh_token: tokens.refresh_token,
      })
      const rotated = await (await request('/oauth/token', refresh)).json()
      assert.ok(rotated.access_token)
      assert.equal((await rpc('ping', {}, tokens.access_token)).status, 401)
      assert.equal((await request('/oauth/token', refresh)).status, 400)
      await request(
        '/oauth/revoke',
        new URLSearchParams({ token: rotated.refresh_token, client_id: registered.client_id }),
      )
      assert.equal((await rpc('ping', {}, rotated.access_token)).status, 401)
    })
  } finally {
    globalThis.fetch = original
    await Promise.allSettled(pending)
    await mf.dispose()
  }
})
