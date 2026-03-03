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
    const scan = await this.scanService.create(dto);
    await this.scanQueue.enqueue(scan.id);
    return scan as unknown as ScanResultDto;
  }

  @Get('scan/:id')
  @ApiOperation({ summary: 'get scan status and results' })
  @ApiResponse({ status: 200, type: ScanResultDto })
  async getScan(@Param('id') id: string): Promise<ScanResultDto> {
    const scan = await this.scanService.findOne(id);
    const vulns = await this.scanService.getVulns(id);
    return { ...scan, vulns } as unknown as ScanResultDto;
  }

  @Delete('scan/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'cancel an active scan' })
  async cancelScan(@Param('id') id: string): Promise<void> {
    await this.scanService.cancel(id);
  }

  @Delete('scans/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'permanently delete a scan and its results' })
  async deleteScan(@Param('id') id: string): Promise<void> {
    await this.scanService.deleteScan(id);
  }

  @Delete('scans')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'delete all scans, results, and reports' })
  async deleteAllScans(): Promise<{ deleted: number }> {
    const count = await this.scanService.deleteAllScans();
    return { deleted: count };
  }

  @Get('scans')
  @ApiOperation({ summary: 'list all scans paginated' })
  async listScans(
    @Query('page') page = 1,
    @Query('limit') limit = 20,
  ): Promise<ScanResultDto[]> {
    const all = await this.scanService.findAll();
    const start = (Number(page) - 1) * Number(limit);
    const paged = all.slice(start, start + Number(limit));
    const results: ScanResultDto[] = [];
    for (const s of paged) {
      const vulns = await this.scanService.getVulns(s.id);
      results.push({ ...s, vulns } as unknown as ScanResultDto);
    }
    return results;
  }

  @Get('scan/:id/report')
  @ApiOperation({ summary: 'get report for a completed scan' })
  async getReport(@Param('id') id: string): Promise<{ reportUrl: string }> {
    await this.scanService.findOne(id);
    return { reportUrl: `/reports/${id}.html` };
  }

  @Get('health')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'health check' })
  health(): { status: string; timestamp: string } {
    return { status: 'ok', timestamp: new Date().toISOString() };
  }
}
