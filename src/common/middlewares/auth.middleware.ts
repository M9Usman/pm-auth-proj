import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import { match } from 'path-to-regexp';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const excludedPaths = [
      '/auth/signup',
      '/auth/login',
      '/auth/forgot-password',
      '/auth/reset-password',
      '/auth/resend-otp',
      '/auth/verify-otp',
      '/',
    ];

    // Check if the current path matches any excluded path
    const isExcluded = excludedPaths.some((pathPattern) => {
      const matcher = match(pathPattern, { decode: decodeURIComponent });
      return matcher(req.path);
    });

    if (isExcluded) {
      return next(); // Skip middleware logic for excluded routes
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
