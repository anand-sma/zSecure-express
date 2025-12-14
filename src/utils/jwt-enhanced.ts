import jwt from 'jsonwebtoken';

export interface JwtSignOptions {
  expiresIn?: string | number;
  algorithm?: string;
  issuer?: string;
  audience?: string | string[];
  subject?: string;
}

export interface JwtVerifyOptions {
  algorithms?: string[];
  issuer?: string | string[];
  audience?: string | string[];
  clockTolerance?: number;
}

/**
 * JWT Utility Wrapper
 * 
 * Provides a simplified, type-safe interface for JSON Web Token operations.
 */
export const jwtUtils = {
  /**
   * Signs a payload and returns a JWT string.
   * @param payload - The data to encode in the token.
   * @param secret - The secret or private key.
   * @param options - Signing options.
   */
  sign: (payload: object, secret: string, options: JwtSignOptions = {}): string => {
    if (!payload || typeof payload !== 'object') {
      throw new Error('Payload must be a non-null object.');
    }
    if (!secret) {
      throw new Error('Secret key is required for signing.');
    }
    
    return jwt.sign(payload, secret, {
      expiresIn: options.expiresIn ?? '1h',
      algorithm: options.algorithm as 'HS256' ?? 'HS256',
      issuer: options.issuer,
      audience: options.audience,
      subject: options.subject
    });
  },

  /**
   * Verifies a JWT and returns the decoded payload.
   * @param token - The JWT string.
   * @param secret - The secret or public key.
   * @param options - Verification options.
   * @throws JsonWebTokenError if verification fails.
   */
  verify: <T = object>(token: string, secret: string, options: JwtVerifyOptions = {}): T => {
    if (!token || !secret) {
      throw new Error('Token and secret are required for verification.');
    }
    
    return jwt.verify(token, secret, {
      algorithms: (options.algorithms as ('HS256' | 'RS256')[]) ?? ['HS256'],
      issuer: options.issuer,
      audience: options.audience,
      clockTolerance: options.clockTolerance ?? 0
    }) as T;
  },

  /**
   * Decodes a JWT without verifying the signature.
   * CAUTION: Do not trust the payload without verification.
   * @param token - The JWT string.
   */
  decode: (token: string): object | string | null => {
    if (!token) return null;
    return jwt.decode(token);
  }
};

// Legacy alias for backwards compatibility
export { jwtUtils as jwt };
