import { Injectable } from '@nestjs/common';
import { AlertsGateway } from '../alerts/alerts.gateway';
import { EngineHeartbeatDto } from './dto/engine-heartbeat.dto';

// The engine reports every few seconds; after this silence it is shown offline.
const ENGINE_OFFLINE_AFTER_MS = 15_000;

export type BlockOrder = { ip: string; seconds: number; reason: string };

@Injectable()
export class EngineService {
  // Servers that authorised capture in .env may start capturing on boot
  // instead of waiting for a confirmed request from JARVIS.
  private captureEnabled =
    process.env.CYBERSEG_CAPTURE_ALLOWED?.trim().toLowerCase() === 'true' &&
    process.env.CYBERSEG_CAPTURE_AUTOSTART?.trim().toLowerCase() === 'true';
  private heartbeat: (EngineHeartbeatDto & { receivedAt: string }) | null = null;
  // The engine owns the firewall: operator orders wait here for its next heartbeat.
  private pendingUnblocks = new Set<string>();
  private pendingBlocks = new Map<string, BlockOrder>();

  constructor(private readonly gateway: AlertsGateway) {}

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
    this.pendingBlocks.delete(ip);
    this.pendingUnblocks.add(ip);
  }

  queueBlock(order: BlockOrder) {
    this.pendingUnblocks.delete(order.ip);
    this.pendingBlocks.set(order.ip, order);
  }

  recordHeartbeat(heartbeat: EngineHeartbeatDto) {
    const { orderResults, ...status } = heartbeat;
    this.heartbeat = { ...status, receivedAt: new Date().toISOString() };
    for (const result of orderResults ?? []) {
      this.gateway.notifyOrder(result);
    }
    const unblock = [...this.pendingUnblocks];
    const block = [...this.pendingBlocks.values()];
    this.pendingUnblocks.clear();
    this.pendingBlocks.clear();
    return { captureEnabled: this.captureEnabled, unblock, block };
  }

  private engineStatus() {
    if (!this.heartbeat) {
      return { online: false };
    }
    const online = Date.now() - Date.parse(this.heartbeat.receivedAt) < ENGINE_OFFLINE_AFTER_MS;
    return { ...this.heartbeat, online, capturing: online && this.heartbeat.capturing };
  }
}
