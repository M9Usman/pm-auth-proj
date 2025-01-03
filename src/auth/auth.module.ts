import { Module } from "@nestjs/common";
import { AuthService } from './auth.service';
import { PrismaService } from "src/prisma.service";
import { AuthController } from "./auth.controller";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { JwtModule } from '@nestjs/jwt';
import config from '../config/config';
@Module({
    controllers:[AuthController],
    providers:[AuthService,PrismaService],
    imports:[
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
          
    ],
})
export class AuthModule{}