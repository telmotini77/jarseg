import { Global, Module } from '@nestjs/common';
import { AlertsController } from './alerts.controller';
import { AlertsGateway } from './alerts.gateway';
import { AlertsService } from './alerts.service';

// Global so blocks and findings can push live updates through the same gateway.
@Global()
@Module({ controllers: [AlertsController], providers: [AlertsService, AlertsGateway], exports: [AlertsGateway] })
export class AlertsModule {}
