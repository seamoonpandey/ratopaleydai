import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanController } from './scan.controller';
import { ScanService } from './scan.service';
import { ScanGateway } from './scan.gateway';
import { QueueModule } from '../queue/queue.module';
import { AuthModule } from '../auth/auth.module';
import { CrawlerModule } from '../crawler/crawler.module';
import { ScanEntity } from './entities/scan.entity';
import { VulnEntity } from './entities/vuln.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([ScanEntity, VulnEntity]),
    forwardRef(() => QueueModule),
    AuthModule,
    CrawlerModule,
  ],
  controllers: [ScanController],
  providers: [ScanService, ScanGateway],
  exports: [ScanService, ScanGateway],
})
export class ScanModule {}
