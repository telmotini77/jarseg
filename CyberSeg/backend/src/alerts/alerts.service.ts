import { Injectable } from '@nestjs/common';
import { Alert, Prisma } from '@prisma/client';
import { PrismaService } from '../prisma.service';
import { CreateAlertDto } from './dto/create-alert.dto';
import { AlertsGateway } from './alerts.gateway';

@Injectable()
export class AlertsService {
  constructor(private readonly prisma: PrismaService, private readonly gateway: AlertsGateway) {}

  async create(dto: CreateAlertDto): Promise<Alert> {
    const alert = await this.prisma.alert.create({
      data: {
        timestamp: new Date(dto.timestamp), sourceIp: dto.sourceIp, destinationIp: dto.destinationIp,
        risk: dto.risk, description: dto.description, score: dto.score, feature: dto.feature as Prisma.InputJsonValue,
      },
    });
    this.gateway.publish(alert);
    return alert;
  }

  list(limit: number): Promise<Alert[]> {
    return this.prisma.alert.findMany({ orderBy: { timestamp: 'desc' }, take: Math.min(Math.max(limit, 1), 100) });
  }
}
