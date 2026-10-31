import { Body, Controller, Get, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { EngineTokenGuard } from '../engine-token.guard';
import { CreateBlockDto, UnblockDto } from './blocks.dto';
import { BlocksService } from './blocks.service';

@Controller('api/blocks')
export class BlocksController {
  constructor(private readonly blocks: BlocksService) {}

  @Get()
  active() {
    return this.blocks.active();
  }

  @Post()
  @UseGuards(EngineTokenGuard)
  @HttpCode(HttpStatus.CREATED)
  record(@Body() payload: CreateBlockDto) {
    return this.blocks.record(payload);
  }

  @Post('unblock')
  @UseGuards(EngineTokenGuard)
  @HttpCode(HttpStatus.OK)
  unblock(@Body() payload: UnblockDto) {
    return this.blocks.unblock(payload.ip);
  }
}
