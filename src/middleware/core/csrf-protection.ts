import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

// --- Interfaces ---

export interface CsrfLogger {
  warn(message: string, meta?: any): void;
  info(message: string, meta?: any): void;
  error(message: string, meta?: any): void;
}

export interface CsrfOptions {
  /**
   * Name of the cookie to store the token.
   * Default: 'XSRF-TOKEN' (compatible with Axios/Angular)
   */
  cookieName?: string;

  /**
   * Name of the header to check for the token.
   * Default: 'X-XSRF-TOKEN'
   */
  headerName?: string;

  /**
   * Size of the token in bytes. Default: 18 (24 chars base64)
   */
  tokenSize?: number;

  /**
   * HTTP Methods to ignore (do not check CSRF).
   * Default: ['GET', 'HEAD', 'OPTIONS']
   */
  ignoreMethods?: string[];

  /**
   * Cookie Options
   */
  cookie?: {
    secure?: boolean;   // Default: true (requires HTTPS)
    sameSite?: 'Strict' | 'Lax' | 'None'; // Default: 'Strict' for aggression
    httpOnly?: boolean; // Default: false (so client JS can read it for Double Submit)
    domain?: string;
    path?: string;
  };

  /**
   * Custom Logger
   */
  logger?: CsrfLogger;
}

// --- Default Logger ---
const defaultLogger: CsrfLogger = {
  warn: (msg, meta) => console.warn(`[CSRF:WARN] ${msg}`, meta || ''),
  info: (msg) => console.log(`[CSRF:INFO] ${msg}`),
  error: (msg, meta) => console.error(`[CSRF:ERROR] ${msg}`, meta || '')
};

// --- Utilities (Zero Dependency) ---

/**
 * Parses the Cookie header string into an object
 */
function parseCookies(req: Request): Record<string, string> {
  const list: Record<string, string> = {};
  const cookieHeader = req.headers?.cookie;
  if (!cookieHeader) return list;

  cookieHeader.split(';').forEach((cookie: string) => {
    let [name, ...rest] = cookie.split('=');
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    if (!value) return;
    list[name] = decodeURIComponent(value);
  });

  return list;
}

/**
 * Generates a cryptographically strong token
 */
function generateToken(size: number): string {
  return crypto.randomBytes(size).toString('base64url'); // slightly shorter/safer than base64
}

/**
 * CSRF Protection Middleware
 * 
 * Implements the "Double Submit Cookie" pattern.
 * 1. Sets a random token in a cookie (readable by client).
 * 2. Client sends this token back in a header (e.g., X-XSRF-TOKEN).
 * 3. Server verifies Cookie Token matches Header Token.
 * 
 * This protects against cross-origin attacks because attackers cannot read the cookie 
 * from a different origin to verify the header.
 */
export function createCsrfMiddleware(options: CsrfOptions = {}) {
  const logger = options.logger || defaultLogger;
  const cookieName = options.cookieName || 'XSRF-TOKEN';
  const headerName = options.headerName || 'X-XSRF-TOKEN';
  const ignoreMethods = new Set(options.ignoreMethods || ['GET', 'HEAD', 'OPTIONS']);
  const tokenSize = options.tokenSize || 18;
  
  // Cookie defaults
  const cookieOpts = {
    secure: options.cookie?.secure ?? true,
    sameSite: options.cookie?.sameSite ?? 'Strict', // Aggressive default
    httpOnly: options.cookie?.httpOnly ?? false, // False by default for Double Submit pattern
    path: options.cookie?.path ?? '/',
    domain: options.cookie?.domain
  };

  return (req: Request, res: Response, next: NextFunction) => {
    // 1. Parse Cookies manually (no dependency needed)
    const cookies = parseCookies(req);
    let token = cookies[cookieName];

    // 2. Ensure Token Exists
    // If no token exists in cookie, generate one and set it
    if (!token) {
      token = generateToken(tokenSize);
      
      let cookieValue = `${cookieName}=${token}; Path=${cookieOpts.path}`;
      if (cookieOpts.secure) cookieValue += '; Secure';
      if (cookieOpts.httpOnly) cookieValue += '; HttpOnly';
      if (cookieOpts.sameSite) cookieValue += `; SameSite=${cookieOpts.sameSite}`;
      if (cookieOpts.domain) cookieValue += `; Domain=${cookieOpts.domain}`;
      
      res.setHeader('Set-Cookie', cookieValue);
    } 
    // Even if it exists, we can ensure it's still set/refreshed if needed, 
    // but typically for CSRF standard cookies last session or longer. 
    // We won't re-set on every request to save overhead unless missing.

    // 3. Check ignore methods
    if (ignoreMethods.has(req.method.toUpperCase())) {
      return next();
    }

    // 4. Validate Token
    // Get token from Header (preferred) or Body (fallback)
    const clientToken = req.headers[headerName.toLowerCase()] || 
                        req.headers[headerName] ||
                        (req.body && req.body._csrf);

    if (!clientToken || clientToken !== token) {
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        logger.warn(`CSRF Attack Detected: Token mismatch or missing from IP ${ip}`, { 
          path: req.path,
          method: req.method,
          hasCookie: !!token,
          hasHeader: !!clientToken
        });

        return res.status(403).json({
            status: 'error',
            code: 'CSRF_INVALID',
            message: 'Invalid or missing CSRF token.'
        });
    }

    next();
  };
}
