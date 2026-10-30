import { IsISO8601, IsNumber, IsObject, IsString, IsIn, MaxLength } from 'class-validator';

export class CreateAlertDto {
  @IsISO8601()
  timestamp!: string;

  @IsString()
  @MaxLength(64)
  sourceIp!: string;

  @IsString()
  @MaxLength(64)
  destinationIp!: string;

  @IsIn(['medium', 'high'])
  risk!: string;

  @IsString()
  @MaxLength(500)
  description!: string;

  @IsNumber()
  score!: number;

  @IsObject()
  feature!: Record<string, unknown>;
}
