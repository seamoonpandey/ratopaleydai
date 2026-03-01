import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';
import { ScanPhase } from '../common/interfaces/scan.interface';
import { Vuln } from '../common/interfaces/vuln.interface';

export interface ProgressPayload {
  scanId: string;
  phase: ScanPhase;
  progress: number;
  message: string;
}

export interface FindingPayload {
  scanId: string;
  vuln: Partial<Vuln>;
}

export interface CompletePayload {
  scanId: string;
  summary: {
    totalParams: number;
    paramsTested: number;
    vulnsFound: number;
    durationMs: number;
  };
  reportUrl?: string;
}

@WebSocketGateway({
  cors: { origin: '*' },
  namespace: '/',
})
export class ScanGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(ScanGateway.name);

  handleConnection(client: Socket) {
    this.logger.log(`client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`client disconnected: ${client.id}`);
  }

  emitProgress(payload: ProgressPayload): void {
    this.server.emit('scan:progress', payload);
  }

  emitFinding(payload: FindingPayload): void {
    this.server.emit('scan:finding', payload);
  }

  emitComplete(payload: CompletePayload): void {
    this.server.emit('scan:complete', payload);
  }

  emitError(scanId: string, message: string): void {
    this.server.emit('scan:error', { scanId, message });
  }
}
