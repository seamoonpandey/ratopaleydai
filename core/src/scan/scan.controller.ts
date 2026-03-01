import {
  Controller,
  Post,
  Get,
  Delete,
  Param,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Query,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { ScanService } from './scan.service';
import { CreateScanDto } from './dto/create-scan.dto';
import { ScanResultDto } from './dto/scan-result.dto';
import { ScanQueueProducer } from '../queue/scan.producer';
import { ApiKeyGuard } from '../auth/api-key.guard';

@ApiTags('scans')
@ApiBearerAuth()
@UseGuards(ApiKeyGuard)
@Controller()
export class ScanController {
  constructor(
    private readonly scanService: ScanService,
    private readonly scanQueue: ScanQueueProducer,
  ) {}

  @Post('scan')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'start a new scan' })
  @ApiResponse({ status: 201, type: ScanResultDto })
  async createScan(@Body() dto: CreateScanDto): Promise<ScanResultDto> {
    const scan = this.scanService.create(dto);
    await this.scanQueue.enqueue(scan.id);
    return scan as unknown as ScanResultDto;
  }

  @Get('scan/:id')
  @ApiOperation({ summary: 'get scan status and results' })
  @ApiResponse({ status: 200, type: ScanResultDto })
  getScan(@Param('id') id: string): ScanResultDto {
    const scan = this.scanService.findOne(id);
    const vulns = this.scanService.getVulns(id);
    return { ...scan, vulns } as unknown as ScanResultDto;
  }

  @Delete('scan/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'cancel an active scan' })
  cancelScan(@Param('id') id: string): void {
    this.scanService.cancel(id);
  }

  @Get('scans')
  @ApiOperation({ summary: 'list all scans paginated' })
  listScans(
    @Query('page') page = 1,
    @Query('limit') limit = 20,
  ): ScanResultDto[] {
    const all = this.scanService.findAll();
    const start = (Number(page) - 1) * Number(limit);
    return all
      .slice(start, start + Number(limit))
      .map((s) => ({ ...s, vulns: this.scanService.getVulns(s.id) }) as unknown as ScanResultDto);
  }

  @Get('scan/:id/report')
  @ApiOperation({ summary: 'get report for a completed scan' })
  getReport(@Param('id') id: string): { reportUrl: string } {
    this.scanService.findOne(id);
    return { reportUrl: `/reports/${id}.html` };
  }

  @Get('health')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'health check' })
  health(): { status: string; timestamp: string } {
    return { status: 'ok', timestamp: new Date().toISOString() };
  }
}
