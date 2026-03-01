import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ContextClientService } from './context-client.service';
import { PayloadClientService } from './payload-client.service';
import { FuzzerClientService } from './fuzzer-client.service';

@Module({
  imports: [
    HttpModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        timeout: config.get<number>('HTTP_TIMEOUT', 30000),
        maxRedirects: 3,
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [ContextClientService, PayloadClientService, FuzzerClientService],
  exports: [ContextClientService, PayloadClientService, FuzzerClientService],
})
export class ModulesBridgeModule {}
