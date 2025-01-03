import { Body, Controller, Get, Post, Req, Res } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';


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
}