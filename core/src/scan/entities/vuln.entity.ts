import {
  Entity,
  PrimaryColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
} from 'typeorm';
import { VulnType, VulnSeverity } from '../../common/interfaces/vuln.interface';
import type { VulnEvidence } from '../../common/interfaces/vuln.interface';
import { ScanEntity } from './scan.entity';

@Entity('vulns')
export class VulnEntity {
  @PrimaryColumn('uuid')
  id!: string;

  @Column('uuid')
  scanId!: string;

  @Column()
  url!: string;

  @Column({ default: '' })
  param!: string;

  @Column({ type: 'text' })
  payload!: string;

  @Column({ type: 'varchar' })
  type!: VulnType;

  @Column({ type: 'varchar', default: VulnSeverity.LOW })
  severity!: VulnSeverity;

  @Column({ type: 'boolean', default: false })
  reflected!: boolean;

  @Column({ type: 'boolean', default: false })
  executed!: boolean;

  @Column({ type: 'simple-json', default: '{}' })
  evidence!: VulnEvidence;

  @CreateDateColumn()
  discoveredAt!: Date;

  @ManyToOne(() => ScanEntity, (s) => s.vulns, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'scanId' })
  scan?: ScanEntity;
}
