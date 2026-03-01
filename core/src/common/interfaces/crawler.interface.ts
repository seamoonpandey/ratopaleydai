export interface DiscoveredParam {
  name: string;
  source: 'query' | 'form' | 'fragment';
  method: 'GET' | 'POST';
  formAction?: string;
}

export interface DiscoveredForm {
  action: string;
  method: 'GET' | 'POST';
  fields: string[];
}

export interface DomSink {
  type: string;
  snippet: string;
  location: string;
}

export interface WafResult {
  detected: boolean;
  name: string | null;
  confidence: number;
}

export interface CrawlResult {
  baseUrl: string;
  urls: string[];
  params: DiscoveredParam[];
  forms: DiscoveredForm[];
  domSinks: DomSink[];
  waf: WafResult;
  durationMs: number;
}
