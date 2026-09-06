import type { CredentialStore } from './store.ts';

export type TenantConnectable = { usable: boolean; connect(): Promise<void>; logout(): Promise<void> };
export type TenantConnector = (host: string, port: number, user: string, pass: string) => TenantConnectable;

export class CredentialUnavailableError extends Error {}

type Entry = { client: TenantConnectable; lastUsed: number };

export class TenantRegistry {
  #credentials: CredentialStore;
  #connector: TenantConnector;
  #max: number;
  #idleMs: number;
  #clock: () => number;
  #entries = new Map<string, Entry>();
  #pending = new Map<string, Promise<TenantConnectable>>();

  constructor(deps: { credentials: CredentialStore; connector: TenantConnector; maxConnections?: number; idleMs?: number; clock?: () => number }) {
    this.#credentials = deps.credentials;
    this.#connector = deps.connector;
    this.#max = deps.maxConnections ?? 50;
    this.#idleMs = deps.idleMs ?? 600_000;
    this.#clock = deps.clock ?? Date.now;
  }

  async get(subject: string): Promise<TenantConnectable> {
    this.sweepIdle();

    const existing = this.#entries.get(subject);
    if (existing?.client.usable) {
      existing.lastUsed = this.#clock();
      return existing.client;
    }

    const inFlight = this.#pending.get(subject);
    if (inFlight) return inFlight;

    const dial = (async () => {
      let cred: { host: string; port: number; appPassword: string } | null;
      try {
        cred = this.#credentials.get(subject);
      } catch {
        // CredentialStore.get can throw (e.g. AES-GCM tag verification failure
        // on a tampered/mismatched row) in addition to returning null. Either
        // way the credential is unusable for this subject -- never surface the
        // raw error and never hand back a connection.
        throw new CredentialUnavailableError(`no valid credential for ${subject}`);
      }
      if (!cred) throw new CredentialUnavailableError(`no valid credential for ${subject}`);
      const client = this.#connector(cred.host, cred.port, subject, cred.appPassword);
      await client.connect();
      this.#entries.set(subject, { client, lastUsed: this.#clock() });
      this.#credentials.touch(subject);
      this.#evictOverCap();
      return client;
    })().finally(() => this.#pending.delete(subject));

    this.#pending.set(subject, dial);
    return dial;
  }

  sweepIdle(): void {
    const now = this.#clock();
    for (const [subject, entry] of this.#entries) {
      if (now - entry.lastUsed > this.#idleMs) {
        entry.client.logout().catch(() => {});
        this.#entries.delete(subject);
      }
    }
  }

  #evictOverCap(): void {
    while (this.#entries.size > this.#max) {
      let oldestKey: string | undefined;
      let oldest = Infinity;
      for (const [subject, entry] of this.#entries) {
        if (entry.lastUsed < oldest) { oldest = entry.lastUsed; oldestKey = subject; }
      }
      if (oldestKey === undefined) break;
      this.#entries.get(oldestKey)!.client.logout().catch(() => {});
      this.#entries.delete(oldestKey);
    }
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.#entries.values()].map((e) => e.client.logout().catch(() => {})));
    this.#entries.clear();
  }
}
