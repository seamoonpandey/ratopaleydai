import {
  IsUrl,
  IsOptional,
  IsInt,
  Min,
  Max,
  IsBoolean,
  IsArray,
  IsIn,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ScanOptionsDto {
  @ApiPropertyOptional({ default: 3 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(10)
  depth?: number = 3;

  @ApiPropertyOptional({ default: 100 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(500)
  maxParams?: number = 100;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  verifyExecution?: boolean = true;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  wafBypass?: boolean = true;

  @ApiPropertyOptional({ default: 50 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(200)
  maxPayloadsPerParam?: number = 50;

  @ApiPropertyOptional({ default: 60000 })
  @IsOptional()
  @IsInt()
  @Min(5000)
  @Max(300000)
  timeout?: number = 60000;

  @ApiPropertyOptional({ default: ['html', 'json'] })
  @IsOptional()
  @IsArray()
  @IsIn(['html', 'json', 'pdf'], { each: true })
  reportFormat?: ('html' | 'json' | 'pdf')[] = ['html', 'json'];
}

export class CreateScanDto {
  @ApiProperty({ example: 'https://target.com' })
  @IsUrl({ require_tld: false })
  url!: string;

  @ApiPropertyOptional()
  @IsOptional()
  options?: ScanOptionsDto;
}
