import { Injectable } from '@nestjs/common';
import { EngineHeartbeatDto } from './dto/engine-heartbeat.dto';

// The engine reports every few seconds; after this silence it is shown offline.
const ENGINE_OFFLINE_AFTER_MS = 15_000;

@Injectable()
export class EngineService {
  // Servers that authorised capture in .env may start capturing on boot
  // instead of waiting for a confirmed request from JARVIS.
  private captureEnabled =
    process.env.CYBERSEG_CAPTURE_ALLOWED?.trim().toLowerCase() === 'true' &&
    process.env.CYBERSEG_CAPTURE_AUTOSTART?.trim().toLowerCase() === 'true';
  private heartbeat: (EngineHeartbeatDto & { receivedAt: string }) | null = null;
  // The engine owns the firewall: unblock orders wait here for its next heartbeat.
  private pendingUnblocks = new Set<string>();

  state() {
    return { captureEnabled: this.captureEnabled, engine: this.engineStatus() };
  }

  start() {
    this.captureEnabled = true;
    return this.state();
  }

  stop() {
    this.captureEnabled = false;
    return this.state();
  }

  queueUnblock(ip: string) {
    this.pendingUnblocks.add(ip);
  }

  recordHeartbeat(heartbeat: EngineHeartbeatDto) {
    this.heartbeat = { ...heartbeat, receivedAt: new Date().toISOString() };
    const unblock = [...this.pendingUnblocks];
    this.pendingUnblocks.clear();
    return { captureEnabled: this.captureEnabled, unblock };
  }

  private engineStatus() {
    if (!this.heartbeat) {
      return { online: false };
    }
    const online = Date.now() - Date.parse(this.heartbeat.receivedAt) < ENGINE_OFFLINE_AFTER_MS;
    return { ...this.heartbeat, online, capturing: online && this.heartbeat.capturing };
  }
}
