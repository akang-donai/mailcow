import { DatabaseSync } from 'node:sqlite';

export function openDb(path: string): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id TEXT PRIMARY KEY,
      client_name TEXT,
      redirect_uris TEXT NOT NULL,
      grant_types TEXT NOT NULL,
      scope TEXT,
      created_at INTEGER NOT NULL,
      last_used_at INTEGER,
      client_secret TEXT,
      client_secret_expires_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS authorization_codes (
      code_hash TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      resource TEXT,
      expires_at INTEGER NOT NULL,
      consumed_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS tokens (
      token_hash TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      client_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      scope TEXT,
      expires_at INTEGER NOT NULL,
      revoked_at INTEGER,
      consumed_at INTEGER,
      rotated_from TEXT
    );
    CREATE TABLE IF NOT EXISTS credentials (
      subject TEXT PRIMARY KEY,
      host TEXT NOT NULL,
      port INTEGER NOT NULL,
      ciphertext TEXT NOT NULL,
      nonce TEXT NOT NULL,
      verified_at INTEGER NOT NULL,
      last_used_at INTEGER,
      invalid_since INTEGER
    );
    CREATE TABLE IF NOT EXISTS pending_authorizations (
      handle_hash TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      state TEXT,
      resource TEXT,
      scopes TEXT,
      expires_at INTEGER NOT NULL,
      browser_token_hash TEXT
    );
  `);

  // CREATE TABLE IF NOT EXISTS does nothing to a table that already exists,
  // so a database created before the consent browser-binding landed would
  // reach the INSERT in PendingStore.save with no such column and crash on
  // every /authorize. Pending rows are ephemeral (10 min TTL), so adding
  // the column nullable is a complete migration; consent.ts treats a null
  // as "no match", which fails closed for any row already in flight.
  ensureColumn(db, 'pending_authorizations', 'browser_token_hash', 'TEXT');

  return db;
}

function ensureColumn(db: DatabaseSync, table: string, column: string, decl: string): void {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (columns.some((c) => c.name === column)) return;
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
}
