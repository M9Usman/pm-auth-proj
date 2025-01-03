import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { MailerModule } from './mailer/mailer.module';
import config from './config/config';

@Module({
  imports: [
    AuthModule,
    MailerModule,
    ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
