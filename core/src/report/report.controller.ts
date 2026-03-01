import {
  Controller,
  Get,
  Param,
  Query,
  Res,
  HttpCode,
  HttpStatus,
  NotFoundException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { ReportService } from './report.service';
import { ScanService } from '../scan/scan.service';
import { ApiKeyGuard } from '../auth/api-key.guard';

@ApiTags('reports')
@ApiBearerAuth()
@UseGuards(ApiKeyGuard)
@Controller('reports')
export class ReportController {
  constructor(
    private readonly reportService: ReportService,
    private readonly scanService: ScanService,
  ) {}

  @Get(':scanId')
  @ApiOperation({ summary: 'get available report formats for a scan' })
  @ApiResponse({ status: 200 })
  getFormats(@Param('scanId') scanId: string) {
    this.scanService.findOne(scanId);
    const formats = this.reportService.getAvailableFormats(scanId);
    return {
      scanId,
      formats,
      links: formats.reduce(
        (acc, fmt) => ({
          ...acc,
          [fmt]: `/reports/${scanId}/download?format=${fmt}`,
        }),
        {} as Record<string, string>,
      ),
    };
  }

  @Get(':scanId/download')
  @ApiOperation({ summary: 'download a report in the requested format' })
  @ApiQuery({ name: 'format', enum: ['html', 'json', 'pdf'], required: false })
  @ApiResponse({ status: 200, description: 'report file' })
  @ApiResponse({ status: 404, description: 'report not found' })
  download(
    @Param('scanId') scanId: string,
    @Query('format') format: string = 'html',
    @Res() res: Response,
  ) {
    this.scanService.findOne(scanId);

    const filePath = this.reportService.getReportPath(scanId, format);
    if (!filePath) {
      throw new NotFoundException(
        `report not found for scan ${scanId} in format ${format}`,
      );
    }

    const contentTypes: Record<string, string> = {
      html: 'text/html',
      json: 'application/json',
      pdf: 'application/pdf',
    };

    const contentType = contentTypes[format] ?? 'application/octet-stream';
    const filename = `redsentinel-${scanId}.${format}`;

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    res.sendFile(filePath);
  }

  @Get(':scanId/regenerate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'regenerate report for a completed scan' })
  @ApiQuery({
    name: 'formats',
    required: false,
    description: 'comma-separated list: html,json,pdf',
  })
  async regenerate(
    @Param('scanId') scanId: string,
    @Query('formats') formatsStr: string = 'html,json',
  ) {
    const scan = this.scanService.findOne(scanId);
    const vulns = this.scanService.getVulns(scanId);
    const formats = formatsStr.split(',').map((f) => f.trim());

    const reportUrl = await this.reportService.generate(
      scanId,
      scan,
      vulns,
      formats,
    );

    return { scanId, reportUrl, formats };
  }
}
