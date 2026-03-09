import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanModule } from './scan/scan.module';
import { ReportModule } from './report/report.module';
import { HealthModule } from './health/health.module';
import { AuthModule } from './auth/auth.module';
import { ScanEntity } from './scan/entities/scan.entity';
import { VulnEntity } from './scan/entities/vuln.entity';
import { UserEntity } from './auth/entities/user.entity';
import { InitialSchema1709420400000 } from './migrations/1709420400000-InitialSchema';
import { AddUserEntity1710000000000 } from './migrations/1710000000000-AddUserEntity';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    ThrottlerModule.forRoot([{ ttl: 60000, limit: 100 }]),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const isProd = config.get('NODE_ENV') === 'production';
        const url = config.get<string>('DATABASE_URL');

        const base = url
          ? { url }
          : {
              host: config.get<string>('DB_HOST') ?? 'localhost',
              port: config.get<number>('DB_PORT') ?? 5432,
              username: config.get<string>('DB_USER') ?? 'rs',
              password: config.get<string>('DB_PASS') ?? 'rs',
              database: config.get<string>('DB_NAME') ?? 'redsentinel',
            };

        return {
          type: 'postgres' as const,
          ...base,
          entities: [ScanEntity, VulnEntity, UserEntity],
          migrations: [InitialSchema1709420400000, AddUserEntity1710000000000],
          migrationsRun: true,               // auto-run pending migrations on boot
          migrationsTableName: 'typeorm_migrations',
          synchronize: !isProd,               // only in dev for convenience
          logging: !isProd,
        };
      },
    }),
    AuthModule,
    ScanModule,
    ReportModule,
    HealthModule,
  ],
})
export class AppModule {}
