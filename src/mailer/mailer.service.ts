import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailerService {

    constructor(
            private readonly configService:ConfigService
    ){}

    mailTransport(){
        const transporter = nodemailer.createTransport({
            service:'gmail',
            auth: {
              user: this.configService.get<string>('MAIL_USER'),
              pass: this.configService.get<string>('MAIL_PASSWORD'),
            },
          });

          return transporter;
    }

    async sendMail(to: string, subject: string, text: string, html: string) {
        const transporter = this.mailTransport();
        
        const mailOptions = {
            from: this.configService.get<string>('MAIL_USER'),
            to,
            subject,
            text,
            html,
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log(`Email sent to ${to}`);
        } catch (error) {
            console.error(`Failed to send email to ${to}: ${error.message}`);
            throw new Error('Email sending failed');
        }
    }
    async sendPasswordResetlink(to: string, token:string) {
        const resetLink = `http://Customeapp.com/resetPassword?token=${token}`;
        const transporter = this.mailTransport();
        const mailOptions = {
            from: this.configService.get<string>('MAIL_USER'),
            to,
            subject:'Password Reset Requested',
            html:`<p>Your have Requested a Password Reset Link.<p> <span style="font-weight:bold;color:red;">If this is not you then Skip this Mail.</span><p><a href="${resetLink}">Reset Password.</a></p>`,
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log(`Email sent to ${to}`);
        } catch (error) {
            console.error(`Failed to send email to ${to}: ${error.message}`);
            throw new Error('Email sending failed');
        }
    }


}
