import { WebSocketGateway, WebSocketServer } from '@nestjs/websockets';
import { Server } from 'socket.io';

@WebSocketGateway({ cors: { origin: ['http://127.0.0.1:5178', 'http://localhost:5178'] } })
export class AlertsGateway {
  @WebSocketServer()
  server!: Server;

  publish(alert: unknown) {
    this.server.emit('new_alert', alert);
  }

  // Lets the dashboard refresh blocks and findings without polling.
  notify(event: 'blocks_changed' | 'findings_changed') {
    this.server.emit(event);
  }
}
