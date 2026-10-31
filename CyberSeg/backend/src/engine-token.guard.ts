import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { timingSafeEqual } from 'crypto';

// Write operations and engine control require the shared engine token.
@Injectable()
export class EngineTokenGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<{ headers: Record<string, string | string[] | undefined> }>();
    const received = String(request.headers['x-cyberseg-engine-token'] ?? '');
    const expected = process.env.CYBERSEG_ENGINE_TOKEN || '';
    const left = Buffer.from(received);
    const right = Buffer.from(expected);
    if (!expected || left.length !== right.length || !timingSafeEqual(left, right)) {
      throw new UnauthorizedException('Invalid engine token');
    }
    return true;
  }
}
