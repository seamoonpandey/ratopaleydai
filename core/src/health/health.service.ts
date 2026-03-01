import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface ServiceHealth {
  name: string;
  status: 'up' | 'down';
  latencyMs: number;
  detail?: string;
}

export interface HealthReport {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime: number;
  timestamp: string;
  services: ServiceHealth[];
}

@Injectable()
export class HealthService {
  private readonly logger = new Logger(HealthService.name);
  private readonly startedAt = Date.now();

  private readonly endpoints: { name: string; url: string }[];

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {
    const contextUrl = this.config.get<string>(
      'CONTEXT_URL',
      'http://localhost:5001',
    );
    const payloadGenUrl = this.config.get<string>(
      'PAYLOAD_GEN_URL',
      'http://localhost:5002',
    );
    const fuzzerUrl = this.config.get<string>(
      'FUZZER_URL',
      'http://localhost:5003',
    );

    this.endpoints = [
      { name: 'context-module', url: `${contextUrl}/health` },
      { name: 'payload-gen-module', url: `${payloadGenUrl}/health` },
      { name: 'fuzzer-module', url: `${fuzzerUrl}/health` },
    ];
  }

  async check(): Promise<HealthReport> {
    const results = await Promise.allSettled(
      this.endpoints.map((ep) => this.ping(ep)),
    );

    const services: ServiceHealth[] = results.map((r, i) => {
      if (r.status === 'fulfilled') return r.value;
      return {
        name: this.endpoints[i].name,
        status: 'down' as const,
        latencyMs: -1,
        detail: r.reason?.message ?? 'unreachable',
      };
    });

    const downCount = services.filter((s) => s.status === 'down').length;
    let status: HealthReport['status'] = 'healthy';
    if (downCount === services.length) status = 'unhealthy';
    else if (downCount > 0) status = 'degraded';

    return {
      status,
      uptime: Math.floor((Date.now() - this.startedAt) / 1000),
      timestamp: new Date().toISOString(),
      services,
    };
  }

  private async ping(ep: { name: string; url: string }): Promise<ServiceHealth> {
    const start = Date.now();
    try {
      await firstValueFrom(this.http.get(ep.url, { timeout: 5000 }));
      return {
        name: ep.name,
        status: 'up',
        latencyMs: Date.now() - start,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'unknown';
      this.logger.warn(`health check failed for ${ep.name}: ${msg}`);
      return {
        name: ep.name,
        status: 'down',
        latencyMs: Date.now() - start,
        detail: msg,
      };
    }
  }
}
