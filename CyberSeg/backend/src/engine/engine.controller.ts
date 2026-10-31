import { Body, Controller, Get, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { EngineTokenGuard } from '../engine-token.guard';
import { EngineHeartbeatDto } from './dto/engine-heartbeat.dto';
import { EngineService } from './engine.service';

@Controller('api/engine')
export class EngineController {
  constructor(private readonly engine: EngineService) {}

  @Get('state')
  @UseGuards(EngineTokenGuard)
  state() {
    return this.engine.state();
  }

  // Read-only view for the dashboard: counters and capture state, no controls.
  @Get('status')
  status() {
    return this.engine.state();
  }

  @Post('heartbeat')
  @UseGuards(EngineTokenGuard)
  @HttpCode(HttpStatus.OK)
  heartbeat(@Body() payload: EngineHeartbeatDto) {
    return this.engine.recordHeartbeat(payload);
  }

  @Post('start')
  @UseGuards(EngineTokenGuard)
  start() {
    return this.engine.start();
  }

  @Post('stop')
  @UseGuards(EngineTokenGuard)
  stop() {
    return this.engine.stop();
  }
}
