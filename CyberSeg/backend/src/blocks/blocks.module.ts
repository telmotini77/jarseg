import { Module } from '@nestjs/common';
import { EngineModule } from '../engine/engine.module';
import { BlocksController } from './blocks.controller';
import { BlocksService } from './blocks.service';

@Module({ imports: [EngineModule], controllers: [BlocksController], providers: [BlocksService] })
export class BlocksModule {}
