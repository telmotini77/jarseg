import { IsIn, IsISO8601, IsNumber, IsObject, IsOptional, IsString, MaxLength } from 'class-validator';

export const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

export class CreateAlertDto {
  @IsISO8601()
  timestamp!: string;

  @IsString()
  @MaxLength(64)
  sourceIp!: string;

  @IsString()
  @MaxLength(64)
  destinationIp!: string;

  @IsIn(SEVERITIES)
  risk!: string;

  @IsString()
  @MaxLength(500)
  description!: string;

  @IsNumber()
  score!: number;

  @IsObject()
  feature!: Record<string, unknown>;

  @IsOptional()
  @IsString()
  @MaxLength(40)
  category?: string;

  @IsOptional()
  @IsString()
  @MaxLength(60)
  ruleId?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  mitre?: string;

  @IsOptional()
  @IsString()
  @MaxLength(4)
  layer?: string;

  @IsOptional()
  @IsIn(['engine', 'suricata'])
  sensor?: string;

  @IsOptional()
  @IsIn(['alert', 'blocked', 'not_blocked', 'dry_run', 'block_failed'])
  action?: string;
}
