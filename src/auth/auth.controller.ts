import { Body, Controller, Get, Param, Post, Put, Req, Res, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { LoginDto } from './dtos/login.dto';
import { VerificationOTPDto } from './dtos/verificationOTP.dto';
import { OtpDto } from "./dtos/otp.dto";
import { Cron } from "@nestjs/schedule";
import { AuthGuard } from "src/auth/guards/auth.guard";
import { Request } from "express";
import { ResendOtpDto } from "./dtos/resendOTP.dto";
import { VerifyOtpDto } from "./dtos/verifyOtp.dto";


@Controller('/auth')
export class AuthController{
    constructor(private readonly authService:AuthService){}

    @UseGuards(AuthGuard)
    @Get()
    async getAllUser ():Promise<any>{
        return await this.authService.fetchAllUser();
    }

    @Post('/login')
    async login (@Body() userData:LoginDto):Promise<any>{
        return await this.authService.loginUser(userData);
    }

    @Post('verify-otp')
    async verifyOtp(@Body() body: VerifyOtpDto) {
        const { email, otp } = body;
        return await this.authService.verifyOtp(email, otp);
    }

    @Post('resend-otp')
    async resendOtp(@Body() body: ResendOtpDto) {
        const { email } = body;
        return this.authService.resendOtp(email);
    }

    @Cron('0 * * * *') // Run every hour
    async cleanupExpiredOtps() {
        const { count } = await this.authService.deleteExpiredOtps();
        console.log(`Cleaned up ${count} expired OTPs.`);
    }
    @UseGuards(AuthGuard)
    @Get('/user-data')
    async authHome(@Req() req:Request){
        const user = req.user;
        return {
            message:'Fetching User Data!',
            data:user,
        };
    }
}