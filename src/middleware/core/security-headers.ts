import { Request, Response, NextFunction } from 'express';

export interface SecurityHeadersOptions {
  /**
   * Remove the 'X-Powered-By' header to obscure server technology.
   * Default: true
   */
  removePoweredBy?: boolean;

  /**
   * Set 'Server' header to a generic value or remove it.
   * - string: Set to this value (e.g., 'Apache' to confuse attackers).
   * - null/false: Remove the header (if possible, though Node often forces it).
   * Default: 'Secure-Server'
   */
  fakeServer?: string | null | boolean;

  /**
   * Prevent search engines from indexing the response.
   * Headers: X-Robots-Tag: noindex, nofollow
   * Default: true
   */
  noIndex?: boolean;

  /**
   * Disable browser caching to prevent sensitive data from lingering.
   * Headers: Cache-Control, Pragma, Expires
   * Default: true
   */
  noCache?: boolean;

  /**
   * Clear-Site-Data header to scrub client-side storage (cookies, storage, cache).
   * Useful for logout routes.
   * Values: 'cache', 'cookies', 'storage', 'executionContexts' or '*'
   * Default: null (Disabled)
   */
  clearSiteData?: string | string[] | boolean;
}

/**
 * Privacy & Cache Security Middleware
 * 
 * Focuses on preventing data leakage through caching, search indexing,
 * and server fingerprinting. Complements the main 'helmet' middleware.
 */
export function createSecurityHeadersMiddleware(options: SecurityHeadersOptions = {}) {
  const removePoweredBy = options.removePoweredBy !== false;
  const noIndex = options.noIndex !== false;
  const noCache = options.noCache !== false;
  const fakeServer = options.fakeServer !== undefined ? options.fakeServer : 'Secure-Server';
  
  return (_req: Request, res: Response, next: NextFunction) => {
    // 1. Obfuscation: Remove X-Powered-By
    if (removePoweredBy) {
      res.removeHeader('X-Powered-By');
    }

    // 2. Obfuscation: Server Header
    // Note: Node.js core might still set this if not careful, but usually we can override.
    if (fakeServer) {
        if (typeof fakeServer === 'string') {
            res.setHeader('Server', fakeServer);
        }
    } else if (fakeServer === false || fakeServer === null) {
        res.removeHeader('Server');
    }

    // 3. Privacy: Prevent Indexing
    if (noIndex) {
      res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    }

    // 4. Data Security: Disable Caching
    if (noCache) {
      res.setHeader('Surrogate-Control', 'no-store');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }

    // 5. Cleanup: Clear-Site-Data
    if (options.clearSiteData) {
      if (options.clearSiteData === true || options.clearSiteData === '*') {
        res.setHeader('Clear-Site-Data', '"*"');
      } else if (Array.isArray(options.clearSiteData)) {
         const directives = options.clearSiteData.map(d => `"${d}"`).join(', ');
         res.setHeader('Clear-Site-Data', directives);
      } else if (typeof options.clearSiteData === 'string') {
         res.setHeader('Clear-Site-Data', `"${options.clearSiteData}"`);
      }
    }

    next();
  };
}
