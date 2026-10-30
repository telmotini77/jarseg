import { Module } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { AlertsController } from './alerts.controller';
import { AlertsGateway } from './alerts.gateway';
import { AlertsService } from './alerts.service';

@Module({ controllers: [AlertsController], providers: [PrismaService, AlertsService, AlertsGateway] })
export class AlertsModule {}
