import { Injectable } from '@nestjs/common';
import { AlertsGateway } from '../alerts/alerts.gateway';
import { PrismaService } from '../prisma.service';
import { FindingDto, SyncFindingsDto } from './findings.dto';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

@Injectable()
export class FindingsService {
  constructor(private readonly prisma: PrismaService, private readonly gateway: AlertsGateway) {}

  async list(status: string) {
    const findings = await this.prisma.finding.findMany({
      where: status === 'all' ? {} : { resolved: status === 'resolved' },
      orderBy: { lastSeen: 'desc' },
      take: 500,
    });
    return findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  }

  async upsert(finding: FindingDto) {
    const saved = await this.save(finding);
    this.gateway.notify('findings_changed');
    return saved;
  }

  // A full audit replaces the previous one: what is no longer found is resolved.
  async sync({ source, findings }: SyncFindingsDto) {
    for (const finding of findings) {
      await this.save({ ...finding, source });
    }
    const resolved = await this.prisma.finding.updateMany({
      where: { source, resolved: false, key: { notIn: findings.map((finding) => finding.key) } },
      data: { resolved: true, resolvedAt: new Date() },
    });
    this.gateway.notify('findings_changed');
    return { stored: findings.length, resolved: resolved.count };
  }

  private save(finding: FindingDto) {
    const data = {
      source: finding.source, severity: finding.severity, category: finding.category, title: finding.title,
      detail: finding.detail, recommendation: finding.recommendation, asset: finding.asset ?? '', mitre: finding.mitre ?? '',
      lastSeen: new Date(), resolved: false, resolvedAt: null,
    };
    return this.prisma.finding.upsert({ where: { key: finding.key }, create: { key: finding.key, ...data }, update: data });
  }
}
