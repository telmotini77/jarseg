import { Injectable } from '@nestjs/common';
import { Alert, Block, Finding } from '@prisma/client';
import { Workbook } from 'exceljs';
import PDFDocument = require('pdfkit');
import { PrismaService } from '../prisma.service';
import { ACTION_LABEL, CATEGORY_LABEL, SEVERITY_LABEL, label } from './labels';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const MAX_ROWS = 50_000;

export type ReportData = { days: number; since: Date; generatedAt: Date; alerts: Alert[]; blocks: Block[]; findings: Finding[] };

const formatDate = (value: Date | null) => (value ? value.toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '');

@Injectable()
export class ReportService {
  constructor(private readonly prisma: PrismaService) {}

  async collect(days: number): Promise<ReportData> {
    const generatedAt = new Date();
    const since = new Date(generatedAt.getTime() - days * 86_400_000);
    const [alerts, blocks, findings] = await Promise.all([
      this.prisma.alert.findMany({ where: { timestamp: { gte: since } }, orderBy: { timestamp: 'desc' }, take: MAX_ROWS }),
      this.prisma.block.findMany({ where: { blockedAt: { gte: since } }, orderBy: { blockedAt: 'desc' }, take: MAX_ROWS }),
      this.prisma.finding.findMany({ where: { resolved: false }, orderBy: { lastSeen: 'desc' } }),
    ]);
    findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
    return { days, since, generatedAt, alerts, blocks, findings };
  }

  csv(data: ReportData): Buffer {
    const header = ['Fecha (UTC)', 'Severidad', 'Categoría', 'Capa', 'MITRE', 'Sensor', 'Origen', 'Destino', 'Respuesta', 'Regla', 'Descripción', 'Revisada', 'Falso positivo'];
    const escape = (value: unknown) => {
      const text = String(value ?? '');
      // Leading = + - @ would run as a formula when opened in a spreadsheet.
      const safe = /^[=+\-@]/.test(text) ? `'${text}` : text;
      return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
    };
    const rows = data.alerts.map((alert) => [
      formatDate(alert.timestamp), label(SEVERITY_LABEL, alert.risk), label(CATEGORY_LABEL, alert.category), alert.layer, alert.mitre,
      alert.sensor, alert.sourceIp, alert.destinationIp, label(ACTION_LABEL, alert.action), alert.ruleId, alert.description,
      alert.acknowledged ? 'sí' : 'no', alert.falsePositive ? 'sí' : 'no',
    ]);
    const text = [header, ...rows].map((row) => row.map(escape).join(',')).join('\r\n');
    return Buffer.concat([Buffer.from('﻿', 'utf8'), Buffer.from(text, 'utf8')]);  // BOM: Excel reads the accents
  }

  async xlsx(data: ReportData): Promise<Buffer> {
    const book = new Workbook();
    book.creator = 'CyberSeg';
    book.created = data.generatedAt;
    const summary = book.addWorksheet('Resumen');
    summary.columns = [{ header: 'Indicador', key: 'name', width: 42 }, { header: 'Valor', key: 'value', width: 28 }];
    const bySeverity = (severity: string) => data.alerts.filter((alert) => alert.risk === severity).length;
    summary.addRows([
      { name: 'Periodo', value: `Últimos ${data.days} días (desde ${formatDate(data.since)})` },
      { name: 'Generado', value: formatDate(data.generatedAt) },
      { name: 'Alertas', value: data.alerts.length },
      ...SEVERITY_ORDER.map((severity) => ({ name: `  ${SEVERITY_LABEL[severity]}`, value: bySeverity(severity) })),
      { name: 'IPs bloqueadas automáticamente', value: data.alerts.filter((alert) => alert.action === 'blocked').length },
      { name: 'Bloqueos registrados en el periodo', value: data.blocks.length },
      { name: 'Vulnerabilidades abiertas', value: data.findings.length },
    ]);

    const alerts = book.addWorksheet('Alertas');
    alerts.columns = [
      { header: 'Fecha (UTC)', key: 'date', width: 22 }, { header: 'Severidad', key: 'severity', width: 10 },
      { header: 'Categoría', key: 'category', width: 22 }, { header: 'Capa', key: 'layer', width: 6 },
      { header: 'MITRE', key: 'mitre', width: 11 }, { header: 'Sensor', key: 'sensor', width: 10 },
      { header: 'Origen', key: 'source', width: 18 }, { header: 'Destino', key: 'destination', width: 18 },
      { header: 'Respuesta', key: 'action', width: 16 }, { header: 'Regla', key: 'rule', width: 22 },
      { header: 'Descripción', key: 'description', width: 90 }, { header: 'Revisada', key: 'ack', width: 9 },
      { header: 'Falso positivo', key: 'fp', width: 13 },
    ];
    alerts.addRows(data.alerts.map((alert) => ({
      date: formatDate(alert.timestamp), severity: label(SEVERITY_LABEL, alert.risk), category: label(CATEGORY_LABEL, alert.category),
      layer: alert.layer, mitre: alert.mitre, sensor: alert.sensor, source: alert.sourceIp, destination: alert.destinationIp,
      action: label(ACTION_LABEL, alert.action), rule: alert.ruleId, description: alert.description,
      ack: alert.acknowledged ? 'sí' : 'no', fp: alert.falsePositive ? 'sí' : 'no',
    })));

    const blocks = book.addWorksheet('IPs bloqueadas');
    blocks.columns = [
      { header: 'IP', key: 'ip', width: 18 }, { header: 'Severidad', key: 'severity', width: 10 },
      { header: 'Bloqueada (UTC)', key: 'blocked', width: 22 }, { header: 'Expira (UTC)', key: 'expires', width: 22 },
      { header: 'Activa', key: 'active', width: 8 }, { header: 'Reincidencias', key: 'offenses', width: 13 },
      { header: 'Motivo', key: 'reason', width: 90 },
    ];
    blocks.addRows(data.blocks.map((block) => ({
      ip: block.ip, severity: label(SEVERITY_LABEL, block.severity), blocked: formatDate(block.blockedAt), expires: formatDate(block.expiresAt),
      active: block.active && block.expiresAt > data.generatedAt ? 'sí' : 'no', offenses: block.offenses, reason: block.reason,
    })));

    const findings = book.addWorksheet('Vulnerabilidades');
    findings.columns = [
      { header: 'Severidad', key: 'severity', width: 10 }, { header: 'Título', key: 'title', width: 48 },
      { header: 'Activo', key: 'asset', width: 26 }, { header: 'Origen', key: 'source', width: 10 },
      { header: 'Detalle', key: 'detail', width: 70 }, { header: 'Cómo corregirlo', key: 'fix', width: 90 },
      { header: 'Visto por última vez (UTC)', key: 'seen', width: 24 },
    ];
    findings.addRows(data.findings.map((finding) => ({
      severity: label(SEVERITY_LABEL, finding.severity), title: finding.title, asset: finding.asset,
      source: finding.source === 'audit' ? 'Auditoría' : 'Tráfico', detail: finding.detail, fix: finding.recommendation,
      seen: formatDate(finding.lastSeen),
    })));

    for (const sheet of book.worksheets) {
      sheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
      sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0B2A4A' } };
      sheet.views = [{ state: 'frozen', ySplit: 1 }];
      if (sheet.name !== 'Resumen' && sheet.rowCount > 1) {
        sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: sheet.columnCount } };
      }
    }
    return Buffer.from(await book.xlsx.writeBuffer());
  }

  pdf(data: ReportData): Promise<Buffer> {
    // The built-in PDF fonts only cover Latin-1: keep accents, replace symbols.
    const text = (value: unknown) => String(value ?? '').replace(/→/g, '->').replace(/…/g, '...').replace(/[^\x09\x0a\x0d\x20-\xff]/g, '');
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({ size: 'A4', margin: 48, info: { Title: 'Informe de seguridad CyberSeg', Author: 'CyberSeg' } });
      const chunks: Buffer[] = [];
      doc.on('data', (chunk: Buffer) => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      const heading = (title: string) => {
        if (doc.y > 700) doc.addPage();
        doc.moveDown(0.8).font('Helvetica-Bold').fontSize(13).fillColor('#0b2a4a').text(text(title)).moveDown(0.3);
        doc.font('Helvetica').fontSize(9.5).fillColor('#222222');
      };
      const line = (value: string, options: PDFKit.Mixins.TextOptions = {}) => {
        if (doc.y > 760) doc.addPage();
        doc.text(text(value), options);
      };

      doc.font('Helvetica-Bold').fontSize(20).fillColor('#0b2a4a').text('Informe de seguridad CyberSeg');
      doc.font('Helvetica').fontSize(10).fillColor('#555555')
        .text(text(`Periodo: últimos ${data.days} días, desde ${formatDate(data.since)}`))
        .text(text(`Generado: ${formatDate(data.generatedAt)}`));

      heading('Resumen');
      const count = (severity: string) => data.alerts.filter((alert) => alert.risk === severity).length;
      line(`Alertas: ${data.alerts.length}  (críticas ${count('critical')}, altas ${count('high')}, medias ${count('medium')}, bajas ${count('low')})`);
      line(`Respuestas automáticas: ${data.alerts.filter((alert) => alert.action === 'blocked').length} alertas con bloqueo de IP; ${data.blocks.length} bloqueos registrados.`);
      line(`Vulnerabilidades abiertas: ${data.findings.length}`);

      heading('Alertas por categoría');
      const categories = new Map<string, number>();
      for (const alert of data.alerts) categories.set(alert.category, (categories.get(alert.category) ?? 0) + 1);
      for (const [category, total] of [...categories].sort((a, b) => b[1] - a[1])) line(`- ${label(CATEGORY_LABEL, category)}: ${total}`);
      if (!categories.size) line('Sin alertas en el periodo.');

      heading('Principales orígenes de ataque');
      const sources = new Map<string, { total: number; worst: string; blocked: boolean }>();
      for (const alert of data.alerts) {
        const entry = sources.get(alert.sourceIp) ?? { total: 0, worst: 'low', blocked: false };
        entry.total += 1;
        if (SEVERITY_ORDER.indexOf(alert.risk) < SEVERITY_ORDER.indexOf(entry.worst)) entry.worst = alert.risk;
        entry.blocked ||= alert.action === 'blocked';
        sources.set(alert.sourceIp, entry);
      }
      for (const [ip, entry] of [...sources].sort((a, b) => b[1].total - a[1].total).slice(0, 10)) {
        line(`- ${ip}: ${entry.total} alertas, máxima ${label(SEVERITY_LABEL, entry.worst).toLowerCase()}${entry.blocked ? ', bloqueada' : ''}`);
      }
      if (!sources.size) line('Sin orígenes hostiles.');

      heading('Vulnerabilidades abiertas');
      for (const finding of data.findings.slice(0, 40)) {
        line(`[${label(SEVERITY_LABEL, finding.severity)}] ${finding.title} (${finding.asset})`, { continued: false });
        doc.fillColor('#555555');
        line(`   ${finding.recommendation}`);
        doc.fillColor('#222222');
      }
      if (!data.findings.length) line('No hay vulnerabilidades abiertas.');

      heading('Alertas críticas y altas más recientes');
      const severe = data.alerts.filter((alert) => alert.risk === 'critical' || alert.risk === 'high').slice(0, 40);
      for (const alert of severe) {
        line(`${formatDate(alert.timestamp)}  [${label(SEVERITY_LABEL, alert.risk)}] ${label(ACTION_LABEL, alert.action)}${alert.mitre ? `  ${alert.mitre}` : ''}`);
        doc.fillColor('#555555');
        line(`   ${alert.description}`);
        doc.fillColor('#222222');
      }
      if (!severe.length) line('Sin alertas críticas ni altas en el periodo.');
      doc.end();
    });
  }
}
