import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { PythonModuleException } from '../common/exceptions/scan.exceptions';
import { GeneratedPayload } from './payload-client.service';

export interface TestRequest {
  url: string;
  payloads: GeneratedPayload[];
  verifyExecution: boolean;
  timeout: number;
}

export interface FuzzResult {
  payload: string;
  targetParam: string;
  reflected: boolean;
  executed: boolean;
  vuln: boolean;
  type: string;
  evidence: {
    responseCode: number;
    reflectionPosition: string;
    browserAlertTriggered: boolean;
  };
}

export interface TestResponse {
  results: FuzzResult[];
}

@Injectable()
export class FuzzerClientService {
  private readonly logger = new Logger(FuzzerClientService.name);
  private readonly baseUrl: string;

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {
    this.baseUrl = this.config.get<string>('FUZZER_URL', 'http://localhost:5003');
  }

  async test(req: TestRequest): Promise<TestResponse> {
    try {
      const { data } = await firstValueFrom(
        this.http.post<TestResponse>(`${this.baseUrl}/test`, {
          url: req.url,
          payloads: req.payloads,
          verify_execution: req.verifyExecution,
          timeout: req.timeout,
        }),
      );
      this.logger.log(
        `fuzzer tested ${req.payloads.length} payloads → ${data.results.filter((r) => r.vuln).length} vulns`,
      );
      return data;
    } catch (err: any) {
      const detail = err?.response?.data?.detail ?? err?.message ?? 'unknown';
      throw new PythonModuleException('fuzzer', detail);
    }
  }
}
