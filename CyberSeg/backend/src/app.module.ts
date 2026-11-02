import { Module } from '@nestjs/common';
import { AlertsModule } from './alerts/alerts.module';
import { AuthModule } from './auth/auth.module';
import { BlocksModule } from './blocks/blocks.module';
import { EngineModule } from './engine/engine.module';
import { ExportController } from './export/export.controller';
import { ReportService } from './export/report.service';
import { FindingsModule } from './findings/findings.module';
import { HealthController } from './health.controller';
import { ManageModule } from './manage/manage.module';
import { PrismaModule } from './prisma.module';
import { StatsController } from './stats/stats.controller';

@Module({
  imports: [PrismaModule, AuthModule, AlertsModule, EngineModule, BlocksModule, FindingsModule, ManageModule],
  controllers: [HealthController, StatsController, ExportController],
  providers: [ReportService],
})
export class AppModule {}
