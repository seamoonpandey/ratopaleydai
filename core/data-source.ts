/**
 * Standalone TypeORM DataSource — used ONLY by the typeorm CLI
 * for generating and running migrations.
 *
 * Usage:
 *   npx typeorm migration:run    -d dist/data-source.js
 *   npx typeorm migration:revert -d dist/data-source.js
 *
 * The app itself uses TypeOrmModule.forRootAsync() in AppModule,
 * which reads the same env vars but is configured separately.
 */
import { DataSource } from 'typeorm';
import { ScanEntity } from './src/scan/entities/scan.entity';
import { VulnEntity } from './src/scan/entities/vuln.entity';

const url = process.env.DATABASE_URL;

export default new DataSource({
  type: 'postgres',
  ...(url
    ? { url }
    : {
        host: process.env.DB_HOST ?? 'localhost',
        port: Number(process.env.DB_PORT ?? 5432),
        username: process.env.DB_USER ?? 'rs',
        password: process.env.DB_PASS ?? 'rs',
        database: process.env.DB_NAME ?? 'redsentinel',
      }),
  entities: [ScanEntity, VulnEntity],
  migrations: ['dist/migrations/*.js'],
  migrationsTableName: 'typeorm_migrations',
  logging: true,
});
