import { Body, Controller, HttpCode, HttpStatus, NotFoundException, Param, Post, Req, UseGuards } from '@nestjs/common';
import { IsBoolean, IsInt, IsIP, IsOptional, IsString, Max, MaxLength, Min } from 'class-validator';
import { AlertsGateway } from '../alerts/alerts.gateway';
import { HttpRequest } from '../auth/http';
import { AdminSessionGuard } from '../auth/session.guard';
import { BlocksService } from '../blocks/blocks.service';
import { EngineService } from '../engine/engine.service';
import { FindingsService } from '../findings/findings.service';
import { PrismaService } from '../prisma.service';

class ReviewAlertDto {
  @IsOptional()
  @IsBoolean()
  acknowledged?: boolean;

  @IsOptional()
  @IsBoolean()
  falsePositive?: boolean;
}

class ManualBlockDto {
  @IsIP()
  ip!: string;

  @IsInt()
  @Min(1)
  @Max(720)
  hours!: number;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  reason?: string;
}

class IpDto {
  @IsIP()
  ip!: string;
}

class AcceptFindingDto {
  @IsString()
  @MaxLength(200)
  key!: string;

  @IsBoolean()
  accepted!: boolean;
}

class CaptureDto {
  @IsBoolean()
  enabled!: boolean;
}

// Every change made from the web dashboard goes through here.
@Controller('api/manage')
@UseGuards(AdminSessionGuard)
export class ManageController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly gateway: AlertsGateway,
    private readonly blocks: BlocksService,
    private readonly findings: FindingsService,
    private readonly engine: EngineService,
  ) {}

  @Post('alerts/:id/review')
  @HttpCode(HttpStatus.OK)
  async review(@Param('id') id: string, @Body() payload: ReviewAlertDto) {
    const exists = await this.prisma.alert.findUnique({ where: { id }, select: { id: true } });
    if (!exists) throw new NotFoundException('La alerta ya no existe.');
    const alert = await this.prisma.alert.update({ where: { id }, data: payload });
    this.gateway.notify('alerts_changed');
    return alert;
  }

  @Post('blocks')
  @HttpCode(HttpStatus.ACCEPTED)
  block(@Body() payload: ManualBlockDto, @Req() request: HttpRequest) {
    const by = request.session?.user ?? 'admin';
    this.engine.queueBlock({ ip: payload.ip, seconds: payload.hours * 3600, reason: `Bloqueo manual de ${by}: ${payload.reason || 'sin motivo'}` });
    return { ip: payload.ip, message: 'Orden enviada: el motor aplicará el bloqueo en unos segundos.' };
  }

  @Post('blocks/unblock')
  @HttpCode(HttpStatus.OK)
  unblock(@Body() payload: IpDto) {
    return this.blocks.unblock(payload.ip);
  }

  @Post('findings/accept')
  @HttpCode(HttpStatus.OK)
  async accept(@Body() payload: AcceptFindingDto, @Req() request: HttpRequest) {
    const exists = await this.prisma.finding.findUnique({ where: { key: payload.key }, select: { key: true } });
    if (!exists) throw new NotFoundException('La vulnerabilidad ya no existe.');
    return this.findings.accept(payload.key, payload.accepted, request.session?.user ?? 'admin');
  }

  @Post('capture')
  @HttpCode(HttpStatus.OK)
  capture(@Body() payload: CaptureDto) {
    const state = payload.enabled ? this.engine.start() : this.engine.stop();
    this.gateway.notify('engine_changed');
    return state;
  }
}
