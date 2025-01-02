import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import config from './config/config';

@Module({
  imports: [
    AuthModule,
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
    })],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
