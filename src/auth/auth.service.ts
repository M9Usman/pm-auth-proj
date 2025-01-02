import { PrismaService } from "src/prisma.service";
import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";

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
        
        if (!name || name.trim() === '') {
            throw new BadRequestException('Name cannot be empty.');
        }

        // Email Check
        // const currEmail = await this.prisma.user.findUnique({
        //     where: { email: String(email) },
        // });
         // Validate input
        
        // if (currEmail) {
        //     throw new BadRequestException('Email already exists!');
        // }
    
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
            console.log(error);
            if(error instanceof PrismaClientKnownRequestError){
                switch(error.code){
                    case 'P2002':
                        throw new BadRequestException('Email Already Exsists.');
                    default:
                        throw new InternalServerErrorException('An unexpected error occurred.');    
                }
            }
            // Handle unexpected errors
            throw new InternalServerErrorException('Error while creating user.');
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