import { Body, Controller, Get, HttpCode, HttpStatus, Post, Query, UseGuards } from '@nestjs/common';
import { EngineTokenGuard } from '../engine-token.guard';
import { AlertsService } from './alerts.service';
import { CreateAlertDto } from './dto/create-alert.dto';

@Controller('api/alerts')
export class AlertsController {
  constructor(private readonly alerts: AlertsService) {}

  @Post()
  @UseGuards(EngineTokenGuard)
  @HttpCode(HttpStatus.CREATED)
  create(@Body() payload: CreateAlertDto) {
    return this.alerts.create(payload);
  }

  @Get()
  list(
    @Query('limit') rawLimit = '20',
    @Query('risk') risk?: string,
    @Query('category') category?: string,
    @Query('sensor') sensor?: string,
    @Query('sourceIp') sourceIp?: string,
  ) {
    const limit = Number.parseInt(rawLimit, 10);
    return this.alerts.list({ limit: Number.isFinite(limit) ? limit : 20, risk, category, sensor, sourceIp });
  }
}
