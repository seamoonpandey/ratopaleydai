import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { PythonModuleException } from '../common/exceptions/scan.exceptions';
import { ContextMap } from './context-client.service';

export interface GenerateRequest {
  contexts: ContextMap;
  waf: string;
  maxPayloads: number;
}

export interface GeneratedPayload {
  payload: string;
  target_param: string;
  context: string;
  confidence: number;
  waf_bypass: boolean;
  technique?: string;   // original | mutated | obfuscated:*
  severity?: string;    // high | medium | low
}

export interface GenerateResponse {
  payloads: GeneratedPayload[];
}

@Injectable()
export class PayloadClientService {
  private readonly logger = new Logger(PayloadClientService.name);
  private readonly baseUrl: string;

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {
    this.baseUrl = this.config.get<string>(
      'PAYLOAD_GEN_URL',
      'http://localhost:5002',
    );
  }

  async generate(req: GenerateRequest): Promise<GenerateResponse> {
    try {
      const { data } = await firstValueFrom(
        this.http.post<GenerateResponse>(`${this.baseUrl}/generate`, {
          contexts: req.contexts,
          waf: req.waf,
          max_payloads: req.maxPayloads,
        }),
      );
      this.logger.log(`payload-gen returned ${data.payloads.length} payloads`);
      return data;
    } catch (err: unknown) {
      let detail = 'unknown';
      if (err instanceof Error) {
        detail = err.message;
      } else if (typeof err === 'object' && err !== null && 'response' in err) {
        const axiosErr = err as { response?: { data?: { detail?: string } } };
        detail = axiosErr.response?.data?.detail ?? 'unknown';
      }
      throw new PythonModuleException('payload-gen', detail);
    }
  }
}
