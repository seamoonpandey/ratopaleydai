import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { PythonModuleException } from '../common/exceptions/scan.exceptions';

export interface AnalyzeRequest {
  url: string;
  params: string[];
  waf: string;
}

export type ContextMap = Record<
  string,
  {
    reflects_in: string;
    allowed_chars: string[];
    context_confidence: number;
  }
>;

@Injectable()
export class ContextClientService {
  private readonly logger = new Logger(ContextClientService.name);
  private readonly baseUrl: string;

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {
    this.baseUrl = this.config.get<string>('CONTEXT_URL', 'http://localhost:5001');
  }

  async analyze(req: AnalyzeRequest): Promise<ContextMap> {
    try {
      const { data } = await firstValueFrom(
        this.http.post<ContextMap>(`${this.baseUrl}/analyze`, req),
      );
      this.logger.log(`context module responded for ${req.url}`);
      return data;
    } catch (err: any) {
      const detail = err?.response?.data?.detail ?? err?.message ?? 'unknown';
      throw new PythonModuleException('context', detail);
    }
  }
}
