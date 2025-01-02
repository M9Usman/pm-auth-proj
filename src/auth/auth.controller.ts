import { Body, Controller, Get, Post, Req, Res } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { Request,Response } from "express";
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';


@Controller('/auth')
export class AuthController{
    constructor(private readonly authService:AuthService){}

    @Get()
    async getAllUser (@Req() request:Request,@Res() response:Response):Promise<any>{
        const result = await this.authService.fetchAllUser();
        return response.status(200).json({
            status:'OK',
            message:'Success!',
            result:result,
        });
    }

    @Post('/signup')
    async signup (@Req() request:Request,@Res() response:Response,@Body() signupData:SignupDto):Promise<any>{
        const result = await this.authService.signup(signupData);
        return response.status(200).json({
            status:'OK',
            message:'Created User Successfully!',
            result:result,
        });
    }
    
    @Post('/login')
    async login (@Req() request:Request,@Res() response:Response,@Body() userData:LoginDto):Promise<any>{
        const result = await this.authService.login(userData);
        return response.status(200).json({
            status:'OK',
            message:'Login was Successful!',
            result:result,
        });
    }
}