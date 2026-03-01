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
  target_param: string;
  reflected: boolean;
  executed: boolean;
  vuln: boolean;
  type: string;
  evidence: {
    response_code: number;
    reflection_position: string;
    browser_alert_triggered: boolean;
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
    this.baseUrl = this.config.get<string>(
      'FUZZER_URL',
      'http://localhost:5003',
    );
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
    } catch (err) {
      let detail = 'unknown';
      const errObj = err as Record<string, unknown>;
      if (typeof errObj.response === 'object' && errObj.response !== null) {
        const response = errObj.response as Record<string, unknown>;
        const responseData = response.data as Record<string, unknown>;
        if (
          typeof responseData === 'object' &&
          responseData !== null &&
          'detail' in responseData
        ) {
          detail = String(responseData.detail);
        }
      } else if (typeof errObj.message === 'string') {
        detail = errObj.message;
      }
      throw new PythonModuleException('fuzzer', detail);
    }
  }
}
