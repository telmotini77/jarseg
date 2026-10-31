import { IsIn, IsInt, IsIP, IsISO8601, IsOptional, IsString, MaxLength, Min } from 'class-validator';
import { SEVERITIES } from '../alerts/dto/create-alert.dto';

export class CreateBlockDto {
  @IsIP()
  ip!: string;

  @IsString()
  @MaxLength(300)
  reason!: string;

  @IsIn(SEVERITIES)
  severity!: string;

  @IsOptional()
  @IsString()
  @MaxLength(60)
  ruleId?: string;

  @IsOptional()
  @IsIn(['engine', 'suricata'])
  sensor?: string;

  @IsInt()
  @Min(1)
  seconds!: number;

  @IsISO8601()
  expiresAt!: string;

  @IsInt()
  @Min(1)
  offenses!: number;
}

export class UnblockDto {
  @IsIP()
  ip!: string;
}
