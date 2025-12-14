/**
 * Module declarations for external dependencies that may not have types
 * or need augmentation.
 * 
 * Note: Most modules now have proper @types/* packages. This file is retained
 * for edge cases and optional dependencies.
 */

// Optional peer dependencies that may not be installed
declare module 'rate-limit-redis' {
  import { Store } from 'express-rate-limit';
  interface RedisStoreOptions {
    sendCommand: (...args: string[]) => Promise<any>;
    prefix?: string;
  }
  export default class RedisStore implements Store {
    constructor(options: RedisStoreOptions);
    increment(key: string): Promise<{ totalHits: number; resetTime: Date }>;
    decrement(key: string): Promise<void>;
    resetKey(key: string): Promise<void>;
  }
}

// Faker.js exports
declare module '@faker-js/faker' {
  interface Faker {
    string: {
      uuid(): string;
      alphanumeric(length?: number): string;
    };
    internet: {
      email(): string;
      userName(): string;
    };
    date: {
      recent(): Date;
      past(): Date;
    };
  }
  export const faker: Faker;
}

// jsonwebtoken module declaration
declare module 'jsonwebtoken' {
  export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512' | 'none';
  
  export interface JwtPayload {
    [key: string]: unknown;
    iss?: string;
    sub?: string;
    aud?: string | string[];
    exp?: number;
    nbf?: number;
    iat?: number;
    jti?: string;
  }
  
  export interface SignOptions {
    algorithm?: Algorithm;
    expiresIn?: string | number;
    notBefore?: string | number;
    audience?: string | string[];
    subject?: string;
    issuer?: string;
    jwtid?: string;
    noTimestamp?: boolean;
  }
  
  export interface VerifyOptions {
    algorithms?: Algorithm[];
    audience?: string | string[];
    issuer?: string | string[];
    clockTolerance?: number;
    complete?: boolean;
    ignoreExpiration?: boolean;
    ignoreNotBefore?: boolean;
  }
  
  export function sign(payload: object, secret: string, options?: SignOptions): string;
  export function verify(token: string, secret: string, options?: VerifyOptions): JwtPayload | string;
  export function decode(token: string, options?: { complete?: boolean }): JwtPayload | string | null;
  
  export default {
    sign,
    verify,
    decode
  };
}
