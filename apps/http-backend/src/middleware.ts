import { NextFunction, Request, Response } from "express";
import { JWT_SECRET } from "@repo/backend-common/config";
import jwt, { JsonWebTokenError, TokenExpiredError } from "jsonwebtoken";

// Define a type for your JWT payload
interface UserPayload extends jwt.JwtPayload {
  userId: string; // Or number, depending on your user ID type
}

// Define a custom Request type that includes the userId
// This avoids using `(req as any)` or getting TS errors
export interface AuthRequest extends Request {
  userId?: string; // Make it optional, as it won't exist before middleware
}

export function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "Authorization header missing",
    });
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      message: "Invalid token format. Expected 'Bearer <token>'",
    });
  }

  const token = parts[1]!;

  
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as UserPayload;

    if (!decoded || !decoded.userId) {
      return res.status(403).json({
        message: "Invalid token payload",
      });
    }

    req.userId = decoded.userId;
    next();

  } catch (error) {
    if (error instanceof TokenExpiredError) {
      return res.status(401).json({
        message: "Token has expired",
      });
    }
    if (error instanceof JsonWebTokenError) {
      return res.status(403).json({
        message: "Invalid token",
      });
    }

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}