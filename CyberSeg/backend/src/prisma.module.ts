import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

// One shared database client for every feature module.
@Global()
@Module({ providers: [PrismaService], exports: [PrismaService] })
export class PrismaModule {}
