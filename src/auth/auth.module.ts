import { Module } from "@nestjs/common";
import { AuthService } from './auth.service';
import { PrismaService } from "src/prisma.service";
import { AuthController } from "./auth.controller";
@Module({
    controllers:[AuthController],
    providers:[AuthService,PrismaService],
})
export class AuthModule{}