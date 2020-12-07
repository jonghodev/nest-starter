import { HttpException } from '@nestjs/common';
import { Request } from 'express';

export const tokenExtractor = (req: Request): string | null => {
  const token = req.headers.authorization;
  if (!token) {
    throw new HttpException(
      new CustomException('Authorization header is required.'),
      401,
    );
  }
  return token;
};

export interface JwtPayload {
  email: string;
  sub: string;
  iat: number;
  exp: number;
}

export class ApiResponse {
  success: boolean;
  message: string;
  data: any;

  constructor(success: boolean, message: string, data?: any) {
    this.success = success;
    this.message = message;
    this.data = data;
  }

  get getSuccess() {
    return this.success;
  }

  get getMessage() {
    return this.message;
  }

  get getData() {
    return this.data;
  }

  static create(message: string, data?: any): ApiResponse {
    return new ApiResponse(true, message, data);
  }
}

export class CustomException {
  message: string;

  constructor(message: string) {
    this.message = message;
  }

  get getMessage() {
    return this.message;
  }
}

export class ExceptionResponse {
  statusCode: number;
  timestamp: string;
  path: string;
  success: false = false;
  error: string;

  constructor(
    statusCode: number,
    timestamp: string,
    path: string,
    error: string,
  ) {
    this.statusCode = statusCode;
    this.timestamp = timestamp;
    this.path = path;
    this.error = error;
  }

  get getStatusCode() {
    return this.statusCode;
  }

  get getTimestamp() {
    return this.timestamp;
  }

  get getPath() {
    return this.path;
  }

  get getSuccess() {
    return this.success;
  }

  get getError() {
    return this.error;
  }
}
