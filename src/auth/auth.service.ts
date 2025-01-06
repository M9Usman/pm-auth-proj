import { PrismaService } from "src/prisma.service";
import { BadRequestException, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import * as crypto from 'crypto';
import { MailerService } from '../mailer/mailer.service';
import { ForgotPasswordDto } from "./dtos/forgotPassword.dto";
import { nanoid } from "nanoid";

@Injectable()
export class AuthService{
    
    constructor(private prisma:PrismaService,private jwtService:JwtService,private mailerService: MailerService,  ){}
    
    // Create
    async fetchAllUser() {
        return this.prisma.user.findMany();
    }
    // Create
    async signup(signupData: SignupDto) {
        const { email, password, name } = signupData;
        console.log('****** SignUp Starting ******');
        
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
            return { message: 'Created User successful!',result:create};
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
            where: { email: email },
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

    async generateVerificationOtp(userId: number) {
        // Fetch the user
        const user = await this.prisma.user.findUnique({
            where: { id: +userId },
            select: { email: true, id: true },
        });
    
        if (!user || !user.email) {
            throw new NotFoundException('User not found or email is missing.');
        }
    
        // Check for an existing OTP that is still valid
        const existingOtp = await this.prisma.verificationOtp.findFirst({
            where: {
                userId: user.id,
                expiresAt: { gte: new Date() }, // Check if OTP is not expired
            },
        });
    
        if (existingOtp) {
            throw new BadRequestException('An active OTP already exists. Please wait until it expires.');
        }
    
        // Generate a new OTP
        const otpSimple = crypto.randomInt(100000, 999999).toString();
        const otpHash = await bcrypt.hash(otpSimple, 10); // Hash the OTP
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP expires in 5 minutes
    
        // Save the OTP to the database
        try {
            await this.prisma.verificationOtp.create({
                data: {
                    otp: otpHash,
                    expiresAt,
                    email: user.email,
                    userId: user.id,
                },
            });
        } catch (error) {
            throw new InternalServerErrorException('Error saving OTP to the database.');
        }
    
        // Send OTP via email
        await this.mailerService.sendMail(
            user.email,
            'Your OTP for Email Verification',
            `Your OTP is: ${otpSimple}. It will expire in 5 minutes.`,
            `<p>Your OTP is <strong>${otpSimple}</strong>. It will expire in 5 minutes.</p>`
        );
    
        return { message: 'OTP sent successfully', email: user.email };
    }
    
    async verifyOtp(userId: number, otp: string): Promise<boolean> {
        // Fetch the OTP record for the user
        const verificationOtp = await this.prisma.verificationOtp.findFirst({
            where: {
                userId: +userId,
                expiresAt: { gte: new Date() }, // Ensure OTP is not expired
            },
        });
    
        if (!verificationOtp) {
            throw new BadRequestException('Invalid or expired OTP.');
        }
    
        // Compare the provided OTP with the hashed OTP in the database
        const isOtpValid = await bcrypt.compare(otp, verificationOtp.otp);
    
        if (!isOtpValid) {
            throw new BadRequestException('Invalid OTP.');
        }
    
        // Delete the OTP after successful verification
        try {
            await this.prisma.verificationOtp.delete({
                where: { id: verificationOtp.id },
            });
            return true; // OTP verification was successful, and the record was deleted
        } catch (error) {
            throw new InternalServerErrorException('Error deleting OTP record after verification.');
        }
    }
    

    async deleteExpiredOtps(): Promise<{ count: number }> {
        try {
            const result = await this.prisma.verificationOtp.deleteMany({
                where: {
                    expiresAt: { lt: new Date() }, // Delete OTPs where the expiry date is less than the current date
                },
            });
    
            return { count: result.count }; // Correctly return the count property
        } catch (error) {
            throw new InternalServerErrorException('Error deleting expired OTPs from the database.');
        }
    }    
    
    async changePassword(userId:number,oldPassword:string,newPassword:string){
        // Find User
        const user = await this.prisma.user.findUnique({
            where:{id:+userId}
        });
        if(!user){
            throw new NotFoundException('User not Found... !');
        }
        // Compare old password with the password in DB
        const passwordMatch = await bcrypt.compare(oldPassword,user.password);
        if(!passwordMatch){
            throw new UnauthorizedException('Wrong credentials!');
        } 

        // Change user's password ( AFTER HASING)
        const newHashedPassword = await bcrypt.hash(newPassword,10);
        try{
            const result=  await this.prisma.user.update({
                where: {
                    id: userId, // Replace `userId` with the actual user identifier
                },
                data: {
                    password: newHashedPassword,
                },
            });
            return {
                message:'User Password Changed!',
                result:result,
            };
        }catch(error){
            throw new InternalServerErrorException('Something goes wrong!');
        } 
        
    }

    async forgotPassword(email:string){
        
        const user = await this.prisma.user.findUnique({
            where: { email: email },
        });

        if(user){
            const expiryDate = new Date();
            expiryDate.setHours(expiryDate.getHours()+1);
            
            const resetToken  = nanoid(64);
            const resetTokenDB = await this.prisma.resetPassword.create({
                data:{
                    userId:+user.id,
                    token:resetToken,
                    expiresAt:expiryDate,
                }
            });
            this.mailerService.sendPasswordResetlink(email,resetToken);
        }

        return {message:'Email Sent! Please Check Your Email.'};
    }

    async resetPassword(newPassword: string, token: string) { 
        try {
            const tokenStatus = await this.prisma.resetPassword.findUnique({
                where: { token: token },
            });
        
            if (!tokenStatus) {
                throw new NotFoundException("Invalid token.");
            }
        
            const currentTime = new Date();
            if (tokenStatus.expiresAt < currentTime) {
                throw new UnauthorizedException("Token has expired.");
            }
        
            const hashedPassword = await bcrypt.hash(newPassword, 10);
        
            await this.prisma.user.update({
                where: { id: tokenStatus.userId },
                data: { password: hashedPassword }, 
            });
        
            await this.prisma.resetPassword.delete({
                where: { token: token },
            });
        
            return { message: "Password reset successful." };
        } catch (error) {
            console.error(error);
            throw new InternalServerErrorException("An error occurred while resetting the password.");
        }
    }
    
    
}