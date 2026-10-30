import { Controller, Get } from '@nestjs/common';

@Controller('health')
export class HealthController {
  @Get()
  status() {
    return { service: 'cyberseg', status: 'online' };
  }
}
