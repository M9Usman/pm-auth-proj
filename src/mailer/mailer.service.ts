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
            host: this.configService.get<string>('MAIL_HOST'),
            port: this.configService.get<number>('MAIL_PORT'),
            secure: false, // true for port 465, false for other ports
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

}
