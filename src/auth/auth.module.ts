import { Module } from "@nestjs/common";
import { AuthService } from './auth.service';
import { PrismaService } from "src/prisma.service";
import { AuthController } from "./auth.controller";
import { MailerModule } from "src/mailer/mailer.module";
import { MailerService } from "src/mailer/mailer.service";
import { AuthGuard } from "src/auth/guards/auth.guard";
@Module({
    controllers:[AuthController],
    providers:[AuthService,PrismaService,MailerService,AuthGuard],
    imports:[
        MailerModule
    ],
})
export class AuthModule{}