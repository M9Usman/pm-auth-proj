import { IsNotEmpty } from 'class-validator';

export class OtpDto{
    @IsNotEmpty()
    otp:string;
}