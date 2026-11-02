import { CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService, SESSION_COOKIE } from './auth.service';
import { HttpRequest, cookie } from './http';

// Web management actions: a signed admin session plus an anti-CSRF header.
// Browsers never add custom headers to cross-site form posts, and the cookie
// is SameSite=Strict, so a third-party page cannot trigger these actions.
@Injectable()
export class AdminSessionGuard implements CanActivate {
  constructor(private readonly auth: AuthService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<HttpRequest>();
    const session = this.auth.verify(cookie(request, SESSION_COOKIE));
    if (!session) throw new UnauthorizedException('Inicia sesión de nuevo.');
    if (session.role !== 'admin') throw new ForbiddenException('Tu usuario es de solo lectura.');
    if (request.headers['x-cyberseg-csrf'] !== '1') throw new ForbiddenException('Falta la cabecera anti-CSRF.');
    request.session = session;
    return true;
  }
}
