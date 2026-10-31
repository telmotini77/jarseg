import 'reflect-metadata';
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true, forbidNonWhitelisted: true }));
  app.enableShutdownHooks();
  app.enableCors({ origin: ['http://127.0.0.1:5178', 'http://localhost:5178'] });
  await app.listen(8780, '0.0.0.0');
}
void bootstrap();
