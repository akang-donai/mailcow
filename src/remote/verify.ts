export type Verifiable = { connect(): Promise<void>; logout(): Promise<void> };
export type VerifierFactory = (host: string, port: number, user: string, pass: string) => Verifiable;
export type ImapVerifier = (host: string, port: number, user: string, pass: string) => Promise<boolean>;

export function makeImapVerifier(factory: VerifierFactory): ImapVerifier {
  return async (host, port, user, pass) => {
    const conn = factory(host, port, user, pass);
    try {
      await conn.connect();
    } catch {
      return false;
    }
    try { await conn.logout(); } catch { /* connection proven; logout failure is immaterial */ }
    return true;
  };
}
