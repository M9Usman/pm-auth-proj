import { PrismaService } from "src/prisma.service";
import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';

@Injectable()
export class AuthService{
    constructor(private prisma:PrismaService,private jwtService:JwtService){}
    
    // Create
    async fetchAllUser() {
        return this.prisma.user.findMany();
    }
    // Create
    async signup(signupData: SignupDto) {
        const { email, password, name } = signupData;
        console.log('****** SignUp Starting ******');
        // Email Check
        const currEmail = await this.prisma.user.findUnique({
            where: { email: String(email) },
        });
    
        if (currEmail) {
            throw new BadRequestException('Email already exists!');
        }
    
        // Password
        const hashedPassword = await bcrypt.hash(password, 10);
    
        // Create
        try {
            const create = await this.prisma.user.create({
                data: {
                    name: name,
                    email: email,
                    password: hashedPassword
                }
            });
            return create;
        } catch (error) {
            throw error;
        }
    }
    
    
    // Read
    async login(loginData: LoginDto) {
        const { email, password } = loginData;
        console.log('****** Login Starting ******');
        
        // Email Check
        const user = await this.prisma.user.findUnique({
            where: { email: String(email) },
        });
        if (!user) {
            throw new UnauthorizedException('Wrong Credentials!');
        }
    
        // Password Check
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            throw new UnauthorizedException('Wrong Credentials!');
        }
    
        return { message: 'Login successful', userId: user.id,token: await this.generateUserTokens(user.id) }; // You can return more data as needed
    }
    

    async generateUserTokens(userId){
        // Generate JWT Token
        const accessToken= this.jwtService.sign({userId},{expiresIn:'1h'});
        
        return{
            accessToken,
        };
    }
}