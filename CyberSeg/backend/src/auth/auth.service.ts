import { HttpException, HttpStatus, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';

export type Role = 'admin' | 'viewer';
export type Session = { user: string; role: Role; exp: number };

export const SESSION_COOKIE = 'cyberseg_session';
export const SESSION_SECONDS = 12 * 3600;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60_000;

const digest = (value: string) => createHash('sha256').update(value).digest();

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  // Sessions are signed with a key derived from the engine token, so no extra
  // secret has to be configured; they are invalidated if the token rotates.
  private readonly key = digest(`cyberseg-session:${process.env.CYBERSEG_ENGINE_TOKEN || randomBytes(32).toString('hex')}`);
  private readonly failures = new Map<string, { count: number; first: number; lockedUntil: number }>();

  enabled(): boolean {
    return this.accounts().length > 0;
  }

  login(user: string, password: string, client: string): { token: string; session: Session } {
    const now = Date.now();
    const record = this.failures.get(client);
    if (record && record.lockedUntil > now) {
      throw new HttpException('Demasiados intentos fallidos. Espera 15 minutos.', HttpStatus.TOO_MANY_REQUESTS);
    }
    // Compare against every account in constant time: no early exit reveals
    // which user names exist.
    let match: { user: string; role: Role } | null = null;
    for (const account of this.accounts()) {
      const userOk = timingSafeEqual(digest(user), digest(account.user));
      const passwordOk = timingSafeEqual(digest(password), digest(account.password));
      if (userOk && passwordOk) match = account;
    }
    if (!match) {
      this.recordFailure(client, now);
      this.logger.warn(`Inicio de sesión fallido para "${user.slice(0, 40)}" desde ${client}.`);
      throw new UnauthorizedException('Usuario o contraseña incorrectos.');
    }
    this.failures.delete(client);
    const session: Session = { user: match.user, role: match.role, exp: Math.floor(now / 1000) + SESSION_SECONDS };
    this.logger.log(`Sesión iniciada: ${match.user} (${match.role}) desde ${client}.`);
    return { token: this.sign(session), session };
  }

  verify(token: string | undefined): Session | null {
    if (!token) return null;
    const [payload, signature] = token.split('.');
    if (!payload || !signature) return null;
    const expected = createHmac('sha256', this.key).update(payload).digest();
    const received = Buffer.from(signature, 'base64url');
    if (received.length !== expected.length || !timingSafeEqual(received, expected)) return null;
    try {
      const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Session;
      return session.exp > Date.now() / 1000 && (session.role === 'admin' || session.role === 'viewer') ? session : null;
    } catch {
      return null;
    }
  }

  private sign(session: Session): string {
    const payload = Buffer.from(JSON.stringify(session)).toString('base64url');
    return `${payload}.${createHmac('sha256', this.key).update(payload).digest('base64url')}`;
  }

  private accounts(): { user: string; password: string; role: Role }[] {
    const accounts: { user: string; password: string; role: Role }[] = [];
    if (process.env.CYBERSEG_ADMIN_PASSWORD) {
      accounts.push({ user: process.env.CYBERSEG_ADMIN_USER || 'admin', password: process.env.CYBERSEG_ADMIN_PASSWORD, role: 'admin' });
    }
    if (process.env.CYBERSEG_VIEWER_PASSWORD) {
      accounts.push({ user: process.env.CYBERSEG_VIEWER_USER || 'lector', password: process.env.CYBERSEG_VIEWER_PASSWORD, role: 'viewer' });
    }
    return accounts;
  }

  private recordFailure(client: string, now: number) {
    const record = this.failures.get(client);
    const fresh = !record || now - record.first > LOCK_MS;
    const updated = fresh ? { count: 1, first: now, lockedUntil: 0 } : { ...record, count: record.count + 1 };
    if (updated.count >= MAX_FAILURES) {
      updated.lockedUntil = now + LOCK_MS;
      this.logger.warn(`Acceso web bloqueado 15 minutos para ${client} tras ${updated.count} intentos fallidos.`);
    }
    this.failures.set(client, updated);
    if (this.failures.size > 10_000) {
      for (const [key, value] of this.failures) if (value.lockedUntil < now && now - value.first > LOCK_MS) this.failures.delete(key);
    }
  }
}
