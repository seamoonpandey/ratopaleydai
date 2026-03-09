import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUserEntity1710000000000 implements MigrationInterface {
  name = 'AddUserEntity1710000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "users" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "email" character varying(255) NOT NULL,
        "name" character varying(255),
        "avatar" character varying(500),
        "provider" character varying(50) NOT NULL,
        "providerId" character varying(255) NOT NULL,
        "apiKey" character varying(255),
        "isActive" boolean NOT NULL DEFAULT true,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        "updatedAt" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_users" PRIMARY KEY ("id")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_users_providerId" ON "users" ("providerId")
    `);

    await queryRunner.query(`
      CREATE UNIQUE INDEX "IDX_users_provider_providerId" ON "users" ("provider", "providerId")
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "IDX_users_provider_providerId"`);
    await queryRunner.query(`DROP INDEX "IDX_users_providerId"`);
    await queryRunner.query(`DROP TABLE "users"`);
  }
}
