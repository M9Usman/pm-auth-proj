import { Injectable, NestMiddleware } from "@nestjs/common";
import {NextFunction, Request, Response} from "express";
import * as jwt from 'jsonwebtoken';
@Injectable()
export class AuthMiddleware implements NestMiddleware{
    use(req: Request, res: Response, next:NextFunction){
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
        return res.status(401).json({ message: 'Authentication token is missing.' });
        }

        try {

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req['user'] = decoded; 
        next();
        } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token.' });
        }
    }
    
}