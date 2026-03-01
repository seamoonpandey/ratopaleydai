import { Module } from '@nestjs/common';
import { CrawlerService } from './crawler.service';
import { WafDetectorService } from './waf-detector.service';
import { DomAnalyzerService } from './dom-analyzer.service';

@Module({
  providers: [CrawlerService, WafDetectorService, DomAnalyzerService],
  exports: [CrawlerService],
})
export class CrawlerModule {}
