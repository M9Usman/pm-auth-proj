import { IsNotEmpty } from 'class-validator';

export class VerificationOTPDto{
    @IsNotEmpty()
    id:number;
}