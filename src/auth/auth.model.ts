import { Prisma } from "@prisma/client";

export class User implements Prisma.UserCreateInput{
    id:number;
    name:string;
    email: string;
    password:string;
}