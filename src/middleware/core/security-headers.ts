import { Request, Response, NextFunction } from 'express';

export interface SecurityHeadersOptions {
  /**
   * Prevent search engines from indexing the response.
   * Headers: X-Robots-Tag: noindex, nofollow
   * Default: true
   */
  noIndex?: boolean;

  /**
   * Clear-Site-Data header to scrub client-side storage (cookies, storage, cache).
   * Useful for logout routes.
   * Values: 'cache', 'cookies', 'storage', 'executionContexts' or '*'
   * Default: null (Disabled)
   */
  clearSiteData?: string | string[] | boolean;
}

/**
 * Privacy & Data Cleanup Middleware
 * 
 * Handles privacy signals (Robots) and data sanitization (Clear-Site-Data).
 * Complements the main 'helmet' middleware (which handles Caching, Obfuscation, and Security).
 */
export function createSecurityHeadersMiddleware(options: SecurityHeadersOptions = {}) {
  const noIndex = options.noIndex !== false;
  
  return (_req: Request, res: Response, next: NextFunction) => {
    // 1. Privacy: Prevent Indexing
    if (noIndex) {
      res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    }

    // 2. Cleanup: Clear-Site-Data
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
