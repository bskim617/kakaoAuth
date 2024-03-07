import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as passport from 'passport';
import { HttpExceptionFilter } from './commom/exceptions/http-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalPipes(new ValidationPipe());
  app.use(passport.initialize());

  const config = new DocumentBuilder()
    .setTitle('kakaoAuth')
    .setDescription('카카오 로그인')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('kakaoAuth', app, document);

  app.enableCors({
    origin: ['*'],
    methods: 'GET,PUT,POST,DELETE,PUT,OPTIONS,PATCH',
    credentials: true,
  });
  // app.enableCors();

  app.disable('etag');
  await app.listen(process.env.PORT);
}
bootstrap();
