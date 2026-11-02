import { Module } from '@nestjs/common';
import { BlocksModule } from '../blocks/blocks.module';
import { EngineModule } from '../engine/engine.module';
import { FindingsModule } from '../findings/findings.module';
import { ManageController } from './manage.controller';

@Module({ imports: [BlocksModule, EngineModule, FindingsModule], controllers: [ManageController] })
export class ManageModule {}
