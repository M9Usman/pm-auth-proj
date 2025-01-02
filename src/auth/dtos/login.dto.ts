import {IsEmail, isEmail, IsString } from 'class-validator';

export class LoginDto{
    @IsEmail()
    email:string;
    
    @IsString()
    password:string;
}