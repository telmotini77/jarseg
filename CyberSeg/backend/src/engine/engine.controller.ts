import { Controller, Get, Headers, Post, UnauthorizedException } from '@nestjs/common';
import { timingSafeEqual } from 'crypto';
import { EngineService } from './engine.service';

@Controller('api/engine')
export class EngineController {
  constructor(private readonly engine: EngineService) {}

  @Get('state')
  state(@Headers('x-cyberseg-engine-token') token = '') {
    this.requireEngineToken(token);
    return this.engine.state();
  }

  @Post('start')
  start(@Headers('x-cyberseg-engine-token') token = '') {
    this.requireEngineToken(token);
    return this.engine.start();
  }

  @Post('stop')
  stop(@Headers('x-cyberseg-engine-token') token = '') {
    this.requireEngineToken(token);
    return this.engine.stop();
  }

  private requireEngineToken(received: string) {
    const expected = process.env.CYBERSEG_ENGINE_TOKEN || '';
    const left = Buffer.from(received);
    const right = Buffer.from(expected);
    if (!expected || left.length !== right.length || !timingSafeEqual(left, right)) {
      throw new UnauthorizedException('Invalid engine token');
    }
  }
}
