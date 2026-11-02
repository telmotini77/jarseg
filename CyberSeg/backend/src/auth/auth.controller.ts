import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Res, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { IsString, MaxLength } from 'class-validator';
import { AuthService, SESSION_COOKIE, SESSION_SECONDS } from './auth.service';
import { HttpRequest, HttpResponse, clientAddress, cookie } from './http';

class LoginDto {
  @IsString()
  @MaxLength(100)
  user!: string;

  @IsString()
  @MaxLength(200)
  password!: string;
}

const cookieAttributes = 'Path=/; HttpOnly; Secure; SameSite=Strict';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() payload: LoginDto, @Req() request: HttpRequest, @Res({ passthrough: true }) response: HttpResponse) {
    if (!this.auth.enabled()) {
      throw new ServiceUnavailableException('Define CYBERSEG_ADMIN_PASSWORD en .env para activar el acceso web.');
    }
    const { token, session } = this.auth.login(payload.user, payload.password, clientAddress(request));
    response.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; ${cookieAttributes}; Max-Age=${SESSION_SECONDS}`);
    return { user: session.user, role: session.role };
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Res({ passthrough: true }) response: HttpResponse) {
    response.setHeader('Set-Cookie', `${SESSION_COOKIE}=; ${cookieAttributes}; Max-Age=0`);
    return { ok: true };
  }

  @Get('me')
  me(@Req() request: HttpRequest) {
    const session = this.auth.verify(cookie(request, SESSION_COOKIE));
    if (!session) throw new UnauthorizedException('Sin sesión.');
    return { user: session.user, role: session.role };
  }

  // nginx auth_request: 204 lets the request through, 401 rejects it.
  @Get('check')
  @HttpCode(HttpStatus.NO_CONTENT)
  check(@Req() request: HttpRequest) {
    if (!this.auth.verify(cookie(request, SESSION_COOKIE))) throw new UnauthorizedException();
  }
}
