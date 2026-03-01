import { Injectable, Logger } from '@nestjs/common';
import { WafResult } from '../common/interfaces/crawler.interface';

interface WafSignature {
  name: string;
  headers?: Record<string, RegExp>;
  bodyPatterns?: RegExp[];
  cookies?: RegExp[];
}

const WAF_SIGNATURES: WafSignature[] = [
  {
    name: 'cloudflare',
    headers: {
      server: /cloudflare/i,
      'cf-ray': /.+/,
    },
    cookies: [/__cfduid/i, /cf_clearance/i],
  },
  {
    name: 'akamai',
    headers: {
      'x-akamai-transformed': /.+/,
      server: /akamaighost/i,
    },
  },
  {
    name: 'aws-waf',
    headers: {
      'x-amzn-requestid': /.+/,
    },
    bodyPatterns: [/awselb/i],
  },
  {
    name: 'sucuri',
    headers: {
      'x-sucuri-id': /.+/,
      server: /sucuri/i,
    },
  },
  {
    name: 'imperva',
    headers: {
      'x-cdn': /imperva|incapsula/i,
    },
    cookies: [/visid_incap/i, /incap_ses/i],
  },
  {
    name: 'modsecurity',
    headers: {
      server: /mod_security|modsecurity/i,
    },
    bodyPatterns: [/mod_security|modsecurity/i],
  },
  {
    name: 'wordfence',
    bodyPatterns: [
      /wordfence/i,
      /wfvt_/i,
    ],
  },
  {
    name: 'f5-bigip',
    headers: {
      server: /bigip/i,
    },
    cookies: [/bigipserver/i],
  },
];

@Injectable()
export class WafDetectorService {
  private readonly logger = new Logger(WafDetectorService.name);

  detect(
    headers: Record<string, string>,
    body: string,
    cookies: string[],
  ): WafResult {
    let bestMatch: { name: string; score: number } | null = null;

    for (const sig of WAF_SIGNATURES) {
      let score = 0;
      let checks = 0;

      // check headers
      if (sig.headers) {
        for (const [key, pattern] of Object.entries(sig.headers)) {
          checks++;
          const val = headers[key.toLowerCase()];
          if (val && pattern.test(val)) score++;
        }
      }

      // check body patterns
      if (sig.bodyPatterns) {
        for (const pattern of sig.bodyPatterns) {
          checks++;
          if (pattern.test(body)) score++;
        }
      }

      // check cookies
      if (sig.cookies) {
        for (const pattern of sig.cookies) {
          checks++;
          if (cookies.some((c) => pattern.test(c))) score++;
        }
      }

      if (checks > 0 && score > 0) {
        const confidence = score / checks;
        if (!bestMatch || confidence > bestMatch.score) {
          bestMatch = { name: sig.name, score: confidence };
        }
      }
    }

    if (bestMatch && bestMatch.score >= 0.5) {
      this.logger.log(`waf detected: ${bestMatch.name} (${bestMatch.score})`);
      return {
        detected: true,
        name: bestMatch.name,
        confidence: bestMatch.score,
      };
    }

    return { detected: false, name: null, confidence: 0 };
  }
}
