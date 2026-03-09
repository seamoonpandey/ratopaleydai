import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';
import helmet from 'helmet';
import * as path from 'path';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // security
  app.use(helmet());
  app.enableCors({ origin: process.env.CORS_ORIGIN ?? '*' });

  // static reports directory
  app.useStaticAssets(path.join(process.cwd(), 'reports'), {
    prefix: '/reports/',
  });

  // validation
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  // swagger
  const doc = new DocumentBuilder()
    .setTitle('RedSentinel API')
    .setDescription('AI-powered XSS scanner')
    .setVersion('2.0')
    .addBearerAuth()
    .addApiKey({ type: 'apiKey', in: 'header', name: 'x-api-key' }, 'x-api-key')
    .build();
  const document = SwaggerModule.createDocument(app, doc);
  SwaggerModule.setup('docs', app, document);

  const port = process.env.PORT ?? 3000;
  await app.listen(port);
  console.log(`redsentinel core listening on :${port}`);
  console.log(`swagger docs at http://localhost:${port}/docs`);
}

bootstrap();
