import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ScanQueueProducer, SCAN_QUEUE } from './scan.producer';
import { ScanProcessor } from './scan.processor';
import { ModulesBridgeModule } from '../modules-bridge/bridge.module';
import { ReportModule } from '../report/report.module';

@Module({
  imports: [
    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        connection: {
          host: config.get<string>('REDIS_HOST', 'localhost'),
          port: config.get<number>('REDIS_PORT', 6379),
        },
      }),
      inject: [ConfigService],
    }),
    BullModule.registerQueue({ name: SCAN_QUEUE }),
    ModulesBridgeModule,
    ReportModule,
  ],
  providers: [ScanQueueProducer, ScanProcessor],
  exports: [ScanQueueProducer],
})
export class QueueModule {}
