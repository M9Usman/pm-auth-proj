import { Prisma } from "@prisma/client";
import * as bcrypt from 'bcrypt';

export class User implements Prisma.UserCreateInput{
    id:number;
    name:string;
    email: string;
    password:string;
    // A method to hash the user's password
    async hashPassword() {
        this.password = await bcrypt.hash(this.password, 10);
    }
}