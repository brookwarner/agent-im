CREATE TABLE IF NOT EXISTS event_subscriptions (
  id TEXT PRIMARY KEY,
  principal TEXT NOT NULL,
  event_name TEXT NOT NULL,
  arguments TEXT NOT NULL,
  callback_url TEXT NOT NULL,
  secret TEXT NOT NULL,
  previous_secret TEXT,
  rotated_at INTEGER,
  expires_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS event_deliveries (
  id TEXT PRIMARY KEY,
  subscription_id TEXT NOT NULL REFERENCES event_subscriptions(id) ON DELETE CASCADE,
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  lease_until INTEGER NOT NULL DEFAULT 0,
  last_status INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE(subscription_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON event_deliveries(status, next_attempt_at, lease_until);
CREATE TABLE IF NOT EXISTS auth_rate_limits (key TEXT NOT NULL, window INTEGER NOT NULL, hits INTEGER NOT NULL, PRIMARY KEY(key,window));
CREATE TABLE IF NOT EXISTS oauth_clients (id TEXT PRIMARY KEY, redirect_uris TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_requests (id TEXT PRIMARY KEY, params TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY, principal TEXT NOT NULL, client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash TEXT PRIMARY KEY, principal TEXT NOT NULL, client_id TEXT NOT NULL,
  kind TEXT NOT NULL, expires_at INTEGER NOT NULL, family TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_reply_once ON messages(sender,reply_to) WHERE reply_to IS NOT NULL;
CREATE TABLE IF NOT EXISTS message_keys (
  sender TEXT NOT NULL, client_id TEXT NOT NULL, message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  PRIMARY KEY(sender, client_id)
);

-- Message and event creation share the same transaction, including HTTP/MCP sends.
CREATE TRIGGER IF NOT EXISTS enqueue_message_events AFTER INSERT ON messages
BEGIN
  INSERT OR IGNORE INTO event_deliveries(id, subscription_id, message_id, next_attempt_at, created_at)
  SELECT 'evt_' || NEW.id || '_' || s.id, s.id, NEW.id,
    CAST(unixepoch('subsec') * 1000 AS INTEGER), CAST(unixepoch('subsec') * 1000 AS INTEGER)
  FROM event_subscriptions s JOIN threads t ON t.id = NEW.thread_id
  WHERE s.active = 1 AND s.expires_at > CAST(unixepoch('subsec') * 1000 AS INTEGER)
    AND s.principal != NEW.sender AND t.status = 'open'
    AND (json_extract(s.arguments, '$.thread_id') IS NULL OR json_extract(s.arguments, '$.thread_id') = NEW.thread_id)
    AND EXISTS (SELECT 1 FROM json_each(t.participants) p WHERE json_extract(p.value, '$.id') = s.principal);
END;
