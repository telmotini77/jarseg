import { Module } from '@nestjs/common';
import { AlertsModule } from './alerts/alerts.module';
import { EngineModule } from './engine/engine.module';
import { HealthController } from './health.controller';

@Module({ imports: [AlertsModule, EngineModule], controllers: [HealthController] })
export class AppModule {}
