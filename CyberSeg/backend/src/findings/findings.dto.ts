import { Type } from 'class-transformer';
import { ArrayMaxSize, IsArray, IsIn, IsOptional, IsString, MaxLength, ValidateNested } from 'class-validator';
import { SEVERITIES } from '../alerts/dto/create-alert.dto';

export class FindingDto {
  @IsString()
  @MaxLength(200)
  key!: string;

  @IsIn(SEVERITIES)
  severity!: string;

  @IsString()
  @MaxLength(40)
  category!: string;

  @IsString()
  @MaxLength(200)
  title!: string;

  @IsString()
  @MaxLength(1000)
  detail!: string;

  @IsString()
  @MaxLength(1000)
  recommendation!: string;

  @IsIn(['audit', 'traffic'])
  source!: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  asset?: string;

  @IsOptional()
  @IsString()
  @MaxLength(20)
  mitre?: string;
}

export class SyncFindingsDto {
  @IsIn(['audit', 'traffic'])
  source!: string;

  @IsArray()
  @ArrayMaxSize(500)
  @ValidateNested({ each: true })
  @Type(() => FindingDto)
  findings!: FindingDto[];
}
