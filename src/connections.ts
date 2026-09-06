import type { Account } from './config.ts';

export type Connectable = {
  usable: boolean;
  connect: () => Promise<void>;
  logout: () => Promise<void>;
};

export type Connector = (account: Account) => Connectable;

/**
 * Holds one IMAP connection per account.
 *
 * Connections are opened on first use, not at startup, so an unreachable
 * account does not stop the server from serving the others. ImapFlow does not
 * reconnect on its own and Dovecot drops idle sessions, so every handout
 * re-checks `usable` and redials when needed.
 */
export class ConnectionRegistry {
  #accounts: Map<string, Account>;
  #connector: Connector;
  #clients = new Map<string, Connectable>();
  #pending = new Map<string, Promise<Connectable>>();

  constructor(accounts: Account[], connector: Connector) {
    this.#accounts = new Map(accounts.map((a) => [a.name, a]));
    this.#connector = connector;
  }

  names(): string[] {
    return [...this.#accounts.keys()];
  }

  async get(name: string): Promise<Connectable> {
    const account = this.#accounts.get(name);
    if (!account) {
      throw new Error(`unknown account "${name}"; configured accounts: ${this.names().join(', ')}`);
    }

    const existing = this.#clients.get(name);
    if (existing?.usable) return existing;

    // Collapse concurrent callers onto one dial rather than racing connects.
    const inFlight = this.#pending.get(name);
    if (inFlight) return inFlight;

    const dial = (async () => {
      const client = this.#connector(account);
      await client.connect();
      this.#clients.set(name, client);
      return client;
    })().finally(() => {
      this.#pending.delete(name);
    });

    this.#pending.set(name, dial);
    return dial;
  }

  async closeAll(): Promise<void> {
    await Promise.all(
      [...this.#clients.values()].map((client) => client.logout().catch(() => {})),
    );
    this.#clients.clear();
  }
}
