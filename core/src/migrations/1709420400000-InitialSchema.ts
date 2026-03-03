import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Initial schema — creates the scans and vulns tables.
 *
 * This migration is idempotent: it checks IF NOT EXISTS so it
 * won't fail if the tables were already created by synchronize
 * during early development.
 */
export class InitialSchema1709420400000 implements MigrationInterface {
  name = 'InitialSchema1709420400000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // ── scans table ────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "scans" (
        "id"          uuid            NOT NULL,
        "url"         varchar         NOT NULL,
        "status"      varchar         NOT NULL DEFAULT 'PENDING',
        "phase"       varchar,
        "progress"    integer         NOT NULL DEFAULT 0,
        "options"     jsonb           NOT NULL DEFAULT '{}',
        "error"       text,
        "createdAt"   TIMESTAMP       NOT NULL DEFAULT now(),
        "updatedAt"   TIMESTAMP       NOT NULL DEFAULT now(),
        "completedAt" TIMESTAMP,
        CONSTRAINT "PK_scans" PRIMARY KEY ("id")
      );
    `);

    // ── vulns table ────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "vulns" (
        "id"           uuid            NOT NULL,
        "scanId"       uuid            NOT NULL,
        "url"          varchar         NOT NULL,
        "param"        varchar         NOT NULL DEFAULT '',
        "payload"      text            NOT NULL,
        "type"         varchar         NOT NULL,
        "severity"     varchar         NOT NULL DEFAULT 'LOW',
        "reflected"    boolean         NOT NULL DEFAULT false,
        "executed"     boolean         NOT NULL DEFAULT false,
        "evidence"     jsonb           NOT NULL DEFAULT '{}',
        "discoveredAt" TIMESTAMP       NOT NULL DEFAULT now(),
        CONSTRAINT "PK_vulns" PRIMARY KEY ("id")
      );
    `);

    // ── foreign key ────────────────────────────────────────────
    // Check if FK already exists (idempotent)
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.table_constraints
          WHERE constraint_name = 'FK_vulns_scanId'
            AND table_name = 'vulns'
        ) THEN
          ALTER TABLE "vulns"
            ADD CONSTRAINT "FK_vulns_scanId"
            FOREIGN KEY ("scanId")
            REFERENCES "scans"("id")
            ON DELETE CASCADE
            ON UPDATE NO ACTION;
        END IF;
      END
      $$;
    `);

    // ── indexes ────────────────────────────────────────────────
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_scans_status"
        ON "scans" ("status");
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_scans_createdAt"
        ON "scans" ("createdAt" DESC);
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_vulns_scanId"
        ON "vulns" ("scanId");
    `);

    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_vulns_type"
        ON "vulns" ("type");
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "vulns";`);
    await queryRunner.query(`DROP TABLE IF EXISTS "scans";`);
  }
}
