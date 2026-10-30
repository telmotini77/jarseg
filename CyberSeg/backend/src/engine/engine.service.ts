import { Injectable } from '@nestjs/common';

@Injectable()
export class EngineService {
  private captureEnabled = false;

  state() {
    return { captureEnabled: this.captureEnabled };
  }

  start() {
    this.captureEnabled = true;
    return this.state();
  }

  stop() {
    this.captureEnabled = false;
    return this.state();
  }
}
