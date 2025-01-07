import { Module } from "@nestjs/common";
import { AuthService } from './auth.service';
import { PrismaService } from "src/prisma.service";
import { AuthController } from "./auth.controller";
import { MailerModule } from "src/mailer/mailer.module";
import { MailerService } from "src/mailer/mailer.service";
@Module({
    controllers:[AuthController],
    providers:[AuthService,PrismaService,MailerService],
    imports:[
        MailerModule
    ],
})
export class AuthModule{}