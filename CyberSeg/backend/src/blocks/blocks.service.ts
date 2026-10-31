import { Injectable } from '@nestjs/common';
import { AlertsGateway } from '../alerts/alerts.gateway';
import { EngineService } from '../engine/engine.service';
import { PrismaService } from '../prisma.service';
import { CreateBlockDto } from './blocks.dto';

@Injectable()
export class BlocksService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly engine: EngineService,
    private readonly gateway: AlertsGateway,
  ) {}

  active() {
    return this.prisma.block.findMany({
      where: { active: true, expiresAt: { gt: new Date() } },
      orderBy: { blockedAt: 'desc' },
      take: 500,
    });
  }

  async record(dto: CreateBlockDto) {
    const data = {
      reason: dto.reason, severity: dto.severity, ruleId: dto.ruleId ?? '', sensor: dto.sensor ?? 'engine',
      offenses: dto.offenses, blockedAt: new Date(), expiresAt: new Date(dto.expiresAt), active: true, releasedAt: null,
    };
    const block = await this.prisma.block.upsert({ where: { ip: dto.ip }, create: { ip: dto.ip, ...data }, update: data });
    this.gateway.notify('blocks_changed');
    return block;
  }

  async unblock(ip: string) {
    this.engine.queueUnblock(ip);
    const released = await this.prisma.block.updateMany({ where: { ip, active: true }, data: { active: false, releasedAt: new Date() } });
    this.gateway.notify('blocks_changed');
    return { ip, released: released.count > 0, message: 'El motor eliminará la regla del firewall en su próximo latido.' };
  }
}
