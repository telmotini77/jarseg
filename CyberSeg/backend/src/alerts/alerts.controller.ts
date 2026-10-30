import { Body, Controller, Get, Headers, HttpCode, HttpStatus, Post, Query, UnauthorizedException } from '@nestjs/common';
import { timingSafeEqual } from 'crypto';
import { AlertsService } from './alerts.service';
import { CreateAlertDto } from './dto/create-alert.dto';

@Controller('api/alerts')
export class AlertsController {
  constructor(private readonly alerts: AlertsService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() payload: CreateAlertDto, @Headers('x-cyberseg-engine-token') token = '') {
    this.requireEngineToken(token);
    return this.alerts.create(payload);
  }

  @Get()
  list(@Query('limit') rawLimit = '20') {
    const limit = Number.parseInt(rawLimit, 10);
    return this.alerts.list(Number.isFinite(limit) ? limit : 20);
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
