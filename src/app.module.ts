import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MailerModule } from './mailer/mailer.module';
import config from './config/config';
import { JwtModule } from '@nestjs/jwt';
import { AuthMiddleware } from './common/middlewares/auth.middleware';
import { PrismaService } from './prisma.service';
import { AuthGuard } from './auth/guards/auth.guard';
import { ChatModule } from './chat/chat.module';

@Module({
  imports: [
    AuthModule,
    MailerModule,
    ConfigModule.forRoot({
      isGlobal:true,
      cache:true,
      load:[config],
    }),
    JwtModule.registerAsync({
        imports:[ConfigModule],
        useFactory:async(config)=>({
          secret:config.get('jwt.secret'),
        }),
        global:true,
        inject:[ConfigService]
      }),
    ChatModule,
    ],
  controllers: [AppController],
  providers: [AppService,PrismaService,AuthGuard],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(AuthMiddleware)
    .exclude(
      { path: 'auth/signup', method: RequestMethod.POST },
      { path: 'auth/login', method: RequestMethod.POST },
      { path: 'auth/forgot-password', method: RequestMethod.POST },
      { path: 'auth/reset-password', method: RequestMethod.PUT },
      { path: 'auth/resend-otp', method: RequestMethod.POST },
      { path: 'auth/verify-otp', method: RequestMethod.POST },
      { path: '/', method: RequestMethod.GET },
    )
    .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
  
}
