import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Alert, Prisma } from '@prisma/client';
import { PrismaService } from '../prisma.service';
import { CreateAlertDto } from './dto/create-alert.dto';
import { AlertsGateway } from './alerts.gateway';

export type AlertFilters = { limit: number; risk?: string; category?: string; sensor?: string; sourceIp?: string };

const DAY_MS = 86_400_000;

@Injectable()
export class AlertsService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AlertsService.name);
  private retentionTimer?: NodeJS.Timeout;

  constructor(private readonly prisma: PrismaService, private readonly gateway: AlertsGateway) {}

  onModuleInit() {
    // Old alerts, released blocks and resolved findings are pruned daily so
    // the database stays bounded on a long-running server.
    void this.applyRetention();
    this.retentionTimer = setInterval(() => void this.applyRetention(), DAY_MS);
    this.retentionTimer.unref();
  }

  onModuleDestroy() {
    clearInterval(this.retentionTimer);
  }

  async create(dto: CreateAlertDto): Promise<Alert> {
    const alert = await this.prisma.alert.create({
      data: {
        timestamp: new Date(dto.timestamp), sourceIp: dto.sourceIp, destinationIp: dto.destinationIp,
        risk: dto.risk, description: dto.description, score: dto.score, feature: dto.feature as Prisma.InputJsonValue,
        category: dto.category ?? 'anomaly', ruleId: dto.ruleId ?? '', mitre: dto.mitre ?? '', layer: dto.layer ?? '',
        sensor: dto.sensor ?? 'engine', action: dto.action ?? 'alert',
      },
    });
    this.gateway.publish(alert);
    return alert;
  }

  list(filters: AlertFilters): Promise<Alert[]> {
    const where: Prisma.AlertWhereInput = {};
    if (filters.risk) where.risk = filters.risk;
    if (filters.category) where.category = filters.category;
    if (filters.sensor) where.sensor = filters.sensor;
    if (filters.sourceIp) where.sourceIp = filters.sourceIp;
    return this.prisma.alert.findMany({ where, orderBy: { timestamp: 'desc' }, take: Math.min(Math.max(filters.limit, 1), 200) });
  }

  private async applyRetention() {
    const days = Number.parseInt(process.env.CYBERSEG_RETENTION_DAYS || '90', 10) || 90;
    const cutoff = new Date(Date.now() - days * DAY_MS);
    try {
      const [alerts, blocks, findings] = await Promise.all([
        this.prisma.alert.deleteMany({ where: { timestamp: { lt: cutoff } } }),
        this.prisma.block.deleteMany({ where: { expiresAt: { lt: cutoff } } }),
        this.prisma.finding.deleteMany({ where: { resolved: true, resolvedAt: { lt: cutoff } } }),
      ]);
      if (alerts.count || blocks.count || findings.count) {
        this.logger.log(`Retención ${days} días: ${alerts.count} alertas, ${blocks.count} bloqueos y ${findings.count} hallazgos eliminados.`);
      }
    } catch (error) {
      this.logger.warn(`No se pudo aplicar la retención: ${(error as Error).message}`);
    }
  }
}
