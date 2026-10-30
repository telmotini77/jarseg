import { AuthService } from './auth/auth.service';

export function bootstrap() {
  return new AuthService();
}
