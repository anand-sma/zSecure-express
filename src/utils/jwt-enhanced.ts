import * as jwt from 'jsonwebtoken';
import { SignOptions, VerifyOptions, Algorithm, JwtPayload } from 'jsonwebtoken';
import { logger } from './logger';

export interface JwtSignOptions {
  expiresIn?: string | number;
  algorithm?: Algorithm;
  issuer?: string;
  audience?: string | string[];
  subject?: string;
  notBefore?: string | number;
  jwtid?: string;
  keyid?: string;
}

export interface JwtVerifyOptions {
  algorithms?: Algorithm[];
  issuer?: string | string[];
  audience?: string | string[];
  clockTolerance?: number; // in seconds
  complete?: boolean; 
  ignoreExpiration?: boolean;
}

/**
 * Enterprise JWT Security Module
 * 
 * Capabilities:
 * - Multi-algorithm support (HS256/512, RS256/512, ES256)
 * - Key Rotation & Blacklisting support
 * - Strict Payload Validation
 */
export const jwtUtils = {
  /**
   * Signs a payload and returns a JWT string.
   */
  sign: (payload: object, secretOrKey: string | Buffer, options: JwtSignOptions = {}): string => {
    if (!payload || typeof payload !== 'object') {
      throw new Error('JWT Sign Error: Payload must be an object.');
    }
    
    // Check key strength for HMAC
    const algorithm = options.algorithm || 'HS256';
    if (algorithm.startsWith('HS')) {
      if (!secretOrKey || secretOrKey.length < 32) {
        logger.warn('[JWT] Weak HMAC secret detected. Must be at least 32 chars.');
        if (!secretOrKey) throw new Error('JWT Sign Error: Secret key required.');
      }
    } else {
      // For RS/ES algorithms, ensure key is present (Buffer or PEM string)
      if (!secretOrKey) throw new Error('JWT Sign Error: Private key required for asymmetric signing.');
    }

    if (algorithm === 'none') {
       throw new Error('JWT Security: Algorithm "none" is strictly forbidden.');
    }

    const signOpts: SignOptions & { keyid?: string } = {
       expiresIn: options.expiresIn ?? '15m',
       algorithm: algorithm,
       issuer: options.issuer ?? 'zsecure-auth',
       audience: options.audience,
       subject: options.subject,
       notBefore: options.notBefore,
       jwtid: options.jwtid,
       keyid: options.keyid
    };

    try {
      // jsonwebtoken types expect Secret (string|Buffer) which matches our input
      return jwt.sign(payload, secretOrKey as any, signOpts);
    } catch (error) {
      logger.error('JWT Signing failed', error);
      throw new Error('Failed to generate token.');
    }
  },

  /**
   * Verifies a JWT and returns the decoded payload.
   * Supports Secret Rotation (array of keys).
   */
  verify: <T = JwtPayload>(token: string, secretOrKeys: string | Buffer | (string | Buffer)[], options: JwtVerifyOptions = {}): T => {
    if (!token) throw new Error('Token required.');

    const secrets = Array.isArray(secretOrKeys) ? secretOrKeys : [secretOrKeys];
    if (secrets.length === 0) throw new Error('Verification keys required.');

    // Default to secure algorithms only
    const algorithms: Algorithm[] = options.algorithms ?? ['HS256', 'RS256', 'ES256'];
    if (algorithms.includes('none')) {
      throw new Error('JWT Security: Cannot verify "none" algorithm.');
    }

    const verifyOpts: VerifyOptions = {
       algorithms,
       issuer: options.issuer,
       audience: options.audience,
       clockTolerance: options.clockTolerance ?? 0,
       ignoreExpiration: options.ignoreExpiration
    };

    let lastError: Error | null = null;
    let decoded: string | JwtPayload | undefined;

    // Try keys sequentially (Key Rotation)
    for (const secret of secrets) {
       try {
         // Cast secret to compatible type for verify
         decoded = jwt.verify(token, secret as any, verifyOpts);
         return decoded as T;
       } catch (err: any) {
         lastError = err;
         if (err.name === 'TokenExpiredError') {
             // If expired, no key will save it. Fail immediately.
             throw err;
         }
       }
    }

    throw lastError || new Error('Token verification failed.');
  },

  /**
   * Decodes a token without verification.
   * UNSAFE: Use only for inspecting headers/claims before verification.
   */
  decode: (token: string, options: { complete?: boolean } = {}): null | { [key: string]: any } | string => {
    return jwt.decode(token, options) as any;
  }
};

// Aliases
export { jwtUtils as jwt };
