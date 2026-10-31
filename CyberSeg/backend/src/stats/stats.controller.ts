import { Controller, Get } from '@nestjs/common';
import { PrismaService } from '../prisma.service';

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

type Group<K extends string> = { [key in K]: string } & { _count: { _all: number } };

function counts<K extends string>(rows: Group<K>[], key: K): Record<string, number> {
  return Object.fromEntries(rows.map((row) => [row[key] || 'n/a', row._count._all]));
}

@Controller('api/stats')
export class StatsController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  async summary() {
    const since = new Date(Date.now() - 86_400_000);
    const recent = { timestamp: { gte: since } };
    const [bySeverity, byCategory, byLayer, bySensor, byAction, sources, blocksActive, findings, timeline] = await Promise.all([
      this.prisma.alert.groupBy({ by: ['risk'], where: recent, _count: { _all: true } }),
      this.prisma.alert.groupBy({ by: ['category'], where: recent, _count: { _all: true } }),
      this.prisma.alert.groupBy({ by: ['layer'], where: recent, _count: { _all: true } }),
      this.prisma.alert.groupBy({ by: ['sensor'], where: recent, _count: { _all: true } }),
      this.prisma.alert.groupBy({ by: ['action'], where: recent, _count: { _all: true } }),
      this.prisma.alert.groupBy({ by: ['sourceIp'], where: recent, _count: { _all: true }, orderBy: { _count: { sourceIp: 'desc' } }, take: 10 }),
      this.prisma.block.count({ where: { active: true, expiresAt: { gt: new Date() } } }),
      this.prisma.finding.groupBy({ by: ['severity'], where: { resolved: false }, _count: { _all: true } }),
      this.prisma.$queryRaw<{ hour: Date; count: number }[]>`
        SELECT date_trunc('hour', "timestamp") AS hour, count(*)::int AS count
        FROM "Alert" WHERE "timestamp" >= ${since} GROUP BY 1 ORDER BY 1`,
    ]);

    const topIps = sources.map((row) => row.sourceIp);
    const [details, blocks] = await Promise.all([
      this.prisma.alert.findMany({ where: { ...recent, sourceIp: { in: topIps } }, select: { sourceIp: true, risk: true, category: true, timestamp: true } }),
      this.prisma.block.findMany({ where: { ip: { in: topIps }, active: true, expiresAt: { gt: new Date() } }, select: { ip: true, expiresAt: true } }),
    ]);
    const blockedUntil = new Map(blocks.map((block) => [block.ip, block.expiresAt]));
    const attackers = sources.map((row) => {
      const own = details.filter((item) => item.sourceIp === row.sourceIp);
      return {
        ip: row.sourceIp,
        alerts: row._count._all,
        maxSeverity: own.reduce((max, item) => (SEVERITY_ORDER.indexOf(item.risk) > SEVERITY_ORDER.indexOf(max) ? item.risk : max), 'low'),
        categories: [...new Set(own.map((item) => item.category))],
        lastSeen: own.reduce((latest, item) => (item.timestamp > latest ? item.timestamp : latest), new Date(0)),
        blockedUntil: blockedUntil.get(row.sourceIp) ?? null,
      };
    });

    return {
      windowHours: 24,
      alerts: {
        total: bySeverity.reduce((sum, row) => sum + row._count._all, 0),
        bySeverity: counts(bySeverity, 'risk'),
        byCategory: counts(byCategory, 'category'),
        byLayer: counts(byLayer, 'layer'),
        bySensor: counts(bySensor, 'sensor'),
        byAction: counts(byAction, 'action'),
      },
      timeline: timeline.map((row) => ({ hour: row.hour, count: Number(row.count) })),
      attackers,
      blocksActive,
      findingsOpen: counts(findings, 'severity'),
    };
  }
}
