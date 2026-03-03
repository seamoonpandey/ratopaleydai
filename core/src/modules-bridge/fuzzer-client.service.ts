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
  /** Stored XSS support — url becomes the store (form action) URL */
  storedMode?: boolean;
  displayUrl?: string;          // page where stored content appears
  formFields?: Record<string, string>; // prefilled form fields
  /** Metadata for ML training data collection */
  context?: string;             // dominant context label
  waf?: string;                 // detected WAF type
  allowedChars?: string[];      // allowed special characters
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
    exact_match?: boolean;
    /* DOM-XSS specific fields */
    sink?: string;
    source?: string;
    line?: number;
    snippet?: string;
    script_url?: string;
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
      // Allow considerably more time than the per-payload timeout so the axios
      // call never races the fuzzer's own batch processing. Add 90 s headroom
      // on top of whatever the scan timeout is (minimum 120 s total).
      const axiosTimeoutMs = Math.max(req.timeout + 90_000, 120_000);
      const { data } = await firstValueFrom(
        this.http.post<TestResponse>(
          `${this.baseUrl}/test`,
          {
            url: req.url,
            payloads: req.payloads,
            verify_execution: req.verifyExecution,
            timeout: req.timeout,
            stored_mode: req.storedMode ?? false,
            display_url: req.displayUrl ?? '',
            form_fields: req.formFields ?? {},
            context: req.context ?? null,
            waf: req.waf ?? null,
            allowed_chars: req.allowedChars ?? null,
          },
          { timeout: axiosTimeoutMs },
        ),
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
