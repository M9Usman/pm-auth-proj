import { Injectable, NestMiddleware } from "@nestjs/common";
import { NextFunction, Request, Response } from "express";
import * as jwt from "jsonwebtoken";

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Define excluded routes
    const excludedPaths = [
      '/auth/signup',
      '/auth/login',
      '/auth/forget-password',
      '/auth/reset-password',
      '/auth/resend-otp/*',
      '/auth/verify-otp/*',
      '/',
    ];

    // Check if the current path matches any excluded path
    if (excludedPaths.includes(req.path)) {
      return next(); // Skip authentication for excluded routes
    }

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
