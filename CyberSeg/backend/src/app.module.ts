import { Module } from '@nestjs/common';
import { AlertsModule } from './alerts/alerts.module';
import { BlocksModule } from './blocks/blocks.module';
import { EngineModule } from './engine/engine.module';
import { FindingsModule } from './findings/findings.module';
import { HealthController } from './health.controller';
import { PrismaModule } from './prisma.module';
import { StatsController } from './stats/stats.controller';

@Module({
  imports: [PrismaModule, AlertsModule, EngineModule, BlocksModule, FindingsModule],
  controllers: [HealthController, StatsController],
})
export class AppModule {}
