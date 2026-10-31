import { IsBoolean, IsInt, IsISO8601, IsObject, IsOptional, IsString, MaxLength, Min } from 'class-validator';

export class EngineHeartbeatDto {
  // Sub-reports: active response, Suricata ingestion and server audit.
  @IsOptional()
  @IsObject()
  prevention?: Record<string, unknown>;

  @IsOptional()
  @IsObject()
  suricata?: Record<string, unknown>;

  @IsOptional()
  @IsObject()
  audit?: Record<string, unknown>;

  @IsOptional()
  @IsInt()
  @Min(0)
  detectionsTotal?: number;

  @IsOptional()
  @IsInt()
  @Min(0)
  findingsReported?: number;

  @IsBoolean()
  captureAllowed!: boolean;

  @IsBoolean()
  capturing!: boolean;

  @IsString()
  @MaxLength(64)
  interface!: string;

  @IsISO8601()
  startedAt!: string;

  @IsOptional()
  @IsString()
  @MaxLength(300)
  lastError?: string | null;

  @IsOptional()
  @IsInt()
  @Min(0)
  packetsSeen?: number;

  @IsOptional()
  @IsInt()
  @Min(0)
  portScansDetected?: number;

  @IsOptional()
  @IsInt()
  @Min(0)
  anomaliesDetected?: number;

  @IsOptional()
  @IsBoolean()
  anomalyModelTrained?: boolean;

  @IsOptional()
  @IsInt()
  @Min(0)
  baselineSamples?: number;

  @IsInt()
  @Min(0)
  alertsPublished!: number;

  @IsInt()
  @Min(0)
  alertsFailed!: number;

  @IsInt()
  @Min(0)
  alertsDropped!: number;
}
