import { Controller, Get, Query, StreamableFile } from '@nestjs/common';
import { ReportService } from './report.service';

const days = (raw?: string) => Math.min(Math.max(Number.parseInt(raw ?? '7', 10) || 7, 1), 365);
const stamp = () => new Date().toISOString().slice(0, 10);

// Read-only downloads. Through nginx they require a signed-in session.
@Controller('api/export')
export class ExportController {
  constructor(private readonly reports: ReportService) {}

  @Get('report.pdf')
  async pdf(@Query('days') raw?: string) {
    const buffer = await this.reports.pdf(await this.reports.collect(days(raw)));
    return new StreamableFile(buffer, { type: 'application/pdf', disposition: `attachment; filename="cyberseg-informe-${stamp()}.pdf"` });
  }

  @Get('report.xlsx')
  async xlsx(@Query('days') raw?: string) {
    const buffer = await this.reports.xlsx(await this.reports.collect(days(raw)));
    return new StreamableFile(buffer, {
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      disposition: `attachment; filename="cyberseg-${stamp()}.xlsx"`,
    });
  }

  @Get('alerts.csv')
  async csv(@Query('days') raw?: string) {
    const buffer = this.reports.csv(await this.reports.collect(days(raw)));
    return new StreamableFile(buffer, { type: 'text/csv; charset=utf-8', disposition: `attachment; filename="cyberseg-alertas-${stamp()}.csv"` });
  }
}
