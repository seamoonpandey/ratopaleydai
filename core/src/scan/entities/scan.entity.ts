import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { ScanStatus, ScanPhase } from '../../common/interfaces/scan.interface';
import type { ScanOptions } from '../../common/interfaces/scan.interface';
import { VulnEntity } from './vuln.entity';

@Entity('scans')
export class ScanEntity {
  @PrimaryColumn('uuid')
  id!: string;

  @Column()
  url!: string;

  @Column({ type: 'varchar', default: ScanStatus.PENDING })
  status!: ScanStatus;

  @Column({ type: 'varchar', nullable: true })
  phase?: ScanPhase;

  @Column({ type: 'int', default: 0 })
  progress!: number;

  @Column({ type: 'simple-json', default: '{}' })
  options!: ScanOptions;

  @Column({ type: 'text', nullable: true })
  error?: string;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  @Column({ nullable: true })
  completedAt?: Date;

  @OneToMany(() => VulnEntity, (v) => v.scan, { cascade: true })
  vulns?: VulnEntity[];
}
