import { Body, Controller, Get, Param, Post, Put, Req, Res, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { VerificationOTPDto } from './dtos/verificationOTP.dto';
import { OtpDto } from "./dtos/otp.dto";
import { Cron } from "@nestjs/schedule";
import { ChangePasswordDto } from "./dtos/changePassword.dto";
import { AuthGuard } from "src/auth/guards/auth.guard";
import { ForgotPasswordDto } from "./dtos/forgotPassword.dto";
import { ResetPasswordDto } from "./dtos/resetPassword.dto";
import { Request } from "express";


@Controller('/auth')
export class AuthController{
    constructor(private readonly authService:AuthService){}

    @Get()
    async getAllUser ():Promise<any>{
        return await this.authService.fetchAllUser();
    }

    @Post('/signup')
    async signup (@Body() signupData:SignupDto):Promise<any>{
        return await this.authService.signup(signupData);
    }
    
    @Post('/login')
    async login (@Body() userData:LoginDto):Promise<any>{
        return await this.authService.login(userData);
    }

    @Post('/verify-otp/:id')
    async verifyOTP(@Param() params:VerificationOTPDto,@Body() otp_message:OtpDto){
        const {id} = params;
        const {otp}= otp_message;
        return await this.authService.verifyOtp(id,otp);
        
    }

    @Post('resend-otp/:userId')
    async resendOtp(@Param('userId') userId: number) {
        return this.authService.resendOtp(userId);
    }

    @UseGuards(AuthGuard)
    @Put('change-password')
    async changePassword(@Body() changePasswordDto: ChangePasswordDto, @Req() req:any){
        return this.authService.changePassword(
            req.userId,
            changePasswordDto.oldPassword,
            changePasswordDto.newPassword
        ); 
    }

    @Post('forgot-password')
    async forgotPassword(@Body() forgotPasswordDto:ForgotPasswordDto){
        return this.authService.forgotPassword(forgotPasswordDto.email);
    }

    @Put('reset-password')
    async resetPassword(@Body() restPasswordDto:ResetPasswordDto){
        return this.authService.resetPassword(restPasswordDto.newPassword,restPasswordDto.token);
    }

    @Cron('0 * * * *') // Run every hour
    async cleanupExpiredOtps() {
        const { count } = await this.authService.deleteExpiredOtps();
        console.log(`Cleaned up ${count} expired OTPs.`);
    }
    @Get('authHome')
    async authHome(@Req() req:Request){
        const user = req.user;
        return {
            message:'Welcome Home to Check MiddleWare!',
            data:user,
        };
    }
}