import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';
import { logger } from '../../utils/logger';

// --- Interfaces ---

export interface CsrfOptions {
  /**
   * Name of the cookie to store the token.
   * Default: 'XSRF-TOKEN'
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
   * Strict Origin Verification.
   * If true, checks Origin/Referer headers match the Host header or whitelisted domains.
   * Default: true
   */
  verifyOrigin?: boolean;

  /**
   * Allowed Origins (for verifyOrigin check).
   * e.g. ['https://app.com']
   */
  trustedOrigins?: string[];
}

// --- Utilities ---

function parseCookies(req: Request): Record<string, string> {
  const list: Record<string, string> = {};
  const cookieHeader = req.headers?.cookie;
  if (!cookieHeader) return list;

  cookieHeader.split(';').forEach((cookie: string) => {
    let name;
const parts = cookie.split('=');
name = parts[0];
const rest = parts.slice(1);
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    if (!value) return;
    list[name] = decodeURIComponent(value);
  });

  return list;
}

function generateToken(size: number): string {
  return crypto.randomBytes(size).toString('base64url');
}

/**
 * Enterprise CSRF Protection Middleware
 * 
 * Implements:
 * 1. "Double Submit Cookie" pattern (Stateless yet secure).
 * 2. Strict Origin Verification (Verifying Origin/Referer headers).
 */
export function createCsrfMiddleware(options: CsrfOptions = {}) {
  const cookieName = options.cookieName || 'XSRF-TOKEN';
  const headerName = options.headerName || 'X-XSRF-TOKEN';
  const ignoreMethods = new Set(options.ignoreMethods || ['GET', 'HEAD', 'OPTIONS']);
  const tokenSize = options.tokenSize || 18;
  const verifyOrigin = options.verifyOrigin !== false;
  
  // Cookie defaults
  const cookieOpts = {
    secure: options.cookie?.secure !== false, // Default true
    sameSite: options.cookie?.sameSite ?? 'Strict',
    httpOnly: options.cookie?.httpOnly ?? false, 
    path: options.cookie?.path ?? '/',
    domain: options.cookie?.domain
  };

  return (req: Request, res: Response, next: NextFunction) => {
    // 1. Cookie Management
    const cookies = parseCookies(req);
    let token = cookies[cookieName];

    // Always ensure a token exists for the client to use, even on GET requests
    if (!token) {
      token = generateToken(tokenSize);
      
      let cookieValue = `${cookieName}=${token}; Path=${cookieOpts.path}`;
      if (cookieOpts.secure) cookieValue += '; Secure';
      if (cookieOpts.httpOnly) cookieValue += '; HttpOnly';
      if (cookieOpts.sameSite) cookieValue += `; SameSite=${cookieOpts.sameSite}`;
      if (cookieOpts.domain) cookieValue += `; Domain=${cookieOpts.domain}`;
      
      res.setHeader('Set-Cookie', cookieValue);
    } 

    // 2. Ignore Safe Methods
    if (ignoreMethods.has(req.method.toUpperCase())) {
      return next();
    }

    // 3. Strict Origin Check (Defense in Depth)
    if (verifyOrigin) {
      const origin = req.headers['origin'] || req.headers['referer'];
      if (origin) {
         // Simplest check: Does it match Host?
         // Note: Host header usually includes port in Express if strictly standard, but req.get('host') is easier.
         const host = req.get('host'); 
         
         let isAllowed = false;
         if (host && origin.includes(host)) isAllowed = true;
         if (options.trustedOrigins && options.trustedOrigins.some(o => origin.startsWith(o))) isAllowed = true;
         
         if (!isAllowed) {
            logger.warn(`CSRF Origin Mismatch`, { origin, host, ip: req.ip });
            return res.status(403).json({
               status: 'error',
               code: 'CSRF_ORIGIN_INVALID',
               message: 'Request origin not allowed.'
            });
         }
      } else {
         // If no Origin/Referer, technically suspicious for state-changing requests in modern browsers,
         // but some privacy tools block them. We warn but rely on Token.
         // logger.warn('CSRF: Missing Origin/Referer on POST', { path: req.path });
      }
    }

    // 4. Validate Token (Double Submit)
    const clientToken = req.headers[headerName.toLowerCase()] || 
                        req.headers[headerName] ||
                        (req.body && req.body._csrf);

    if (!clientToken || clientToken !== token) {
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        logger.warn(`CSRF Attack Detected`, { 
          path: req.path,
          method: req.method,
          hasCookie: !!token,
          hasHeader: !!clientToken,
          ip
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
