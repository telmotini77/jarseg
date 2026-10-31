import { Body, Controller, Get, HttpCode, HttpStatus, Post, Query, UseGuards } from '@nestjs/common';
import { EngineTokenGuard } from '../engine-token.guard';
import { FindingDto, SyncFindingsDto } from './findings.dto';
import { FindingsService } from './findings.service';

@Controller('api/findings')
export class FindingsController {
  constructor(private readonly findings: FindingsService) {}

  @Get()
  list(@Query('status') status = 'open') {
    return this.findings.list(status);
  }

  @Post()
  @UseGuards(EngineTokenGuard)
  @HttpCode(HttpStatus.CREATED)
  upsert(@Body() payload: FindingDto) {
    return this.findings.upsert(payload);
  }

  @Post('sync')
  @UseGuards(EngineTokenGuard)
  @HttpCode(HttpStatus.OK)
  sync(@Body() payload: SyncFindingsDto) {
    return this.findings.sync(payload);
  }
}
