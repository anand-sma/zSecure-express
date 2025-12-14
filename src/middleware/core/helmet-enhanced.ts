import { Request, Response, NextFunction } from 'express';

// --- Interfaces ---

export interface HelmetOptions {
  /**
   * Content Security Policy (CSP) options.
   * Controls which resources the user agent is allowed to load.
   */
  contentSecurityPolicy?: {
    useDefaults?: boolean; // If true, adds robust defaults (script-src 'self', etc.)
    directives?: Record<string, string | string[]>;
    reportOnly?: boolean;
  } | boolean;

  /**
   * Cross-Origin Embedder Policy (COEP).
   * Default: 'require-corp'
   */
  crossOriginEmbedderPolicy?: boolean | 'require-corp' | 'credentialless';

  /**
   * Cross-Origin Opener Policy (COOP). 
   * Default: 'same-origin'
   */
  crossOriginOpenerPolicy?: boolean | 'same-origin' | 'same-origin-allow-popups' | 'unsafe-none';

  /**
   * Cross-Origin Resource Policy (CORP).
   * Default: 'same-origin'
   */
  crossOriginResourcePolicy?: boolean | 'same-origin' | 'same-site' | 'cross-origin';

  /**
   * X-DNS-Prefetch-Control.
   * Default: 'off'
   */
  dnsPrefetchControl?: boolean | 'off' | 'on';

  /**
   * X-Frame-Options.
   * Default: 'SAMEORIGIN'
   */
  frameguard?: boolean | 'DENY' | 'SAMEORIGIN';

  /**
   * Strict-Transport-Security (HSTS).
   * Default: max-age=15552000; includeSubDomains
   */
  hsts?: {
    maxAge?: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  } | boolean;

  /**
   * X-Download-Options (IE8 specific). 
   * Default: 'noopen'
   */
  ieNoOpen?: boolean;

  /**
   * X-Content-Type-Options.
   * Default: 'nosniff'
   */
  noSniff?: boolean;

  /**
   * X-Permitted-Cross-Domain-Policies.
   * Default: 'none'
   */
  permittedCrossDomainPolicies?: boolean | 'none' | 'master-only' | 'by-content-type' | 'all';

  /**
   * Referrer-Policy.
   * Default: 'no-referrer'
   */
  referrerPolicy?: boolean | string | string[];

  /**
   * X-XSS-Protection.
   * Default: '0' (Disabled in modern browsers, but some legacy apps need '1; mode=block')
   */
  xssFilter?: boolean | '0' | '1' | '1; mode=block';

  /**
   * Permissions-Policy (formerly Feature-Policy).
   * Dictionary of features to allow/deny. 
   * e.g., { 'camera': '()', 'geolocation': 'self' }
   */
  permissionsPolicy?: Record<string, string> | boolean;
}

/**
 * Enterprise Security Headers Middleware
 * 
 * A zero-dependency, robust implementation of security headers.
 * Protects against XSS, Clickjacking, MIME-sniffing, and ensures SSL enforcement.
 * Includes modern Cross-Origin Isolation headers.
 */
export function createHelmetMiddleware(options: HelmetOptions = {}) {
  // --- HSTS Builder ---
  const getHstsHeader = (): string | null => {
    if (options.hsts === false) return null;
    const opts = typeof options.hsts === 'object' ? options.hsts : {};
    const maxAge = opts.maxAge || 15552000; // 180 days
    let header = `max-age=${maxAge}`;
    if (opts.includeSubDomains !== false) header += '; includeSubDomains';
    if (opts.preload) header += '; preload';
    return header;
  };

  // --- CSP Builder ---
  const getCspHeader = (): { name: string, value: string } | null => {
    if (options.contentSecurityPolicy === false) return null;
    
    const opts = typeof options.contentSecurityPolicy === 'object' ? options.contentSecurityPolicy : {};
    const useDefaults = opts.useDefaults !== false;
    
    let directives: Record<string, string[]> = {};
    
    if (useDefaults) {
      directives = {
        'default-src': ["'self'"],
        'base-uri': ["'self'"],
        'font-src': ["'self'", 'https:', 'data:'],
        'form-action': ["'self'"],
        'frame-ancestors': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'object-src': ["'none'"],
        'script-src': ["'self'"],
        'script-src-attr': ["'none'"],
        'style-src': ["'self'", 'https:', "'unsafe-inline'"],
        'upgrade-insecure-requests': []
      };
    }

    if (opts.directives) {
      for (const [key, val] of Object.entries(opts.directives)) {
        directives[key] = Array.isArray(val) ? val : [val];
      }
    }

    const value = Object.entries(directives)
      .map(([key, vals]) => {
        if (vals.length === 0) return key;
        return `${key} ${vals.join(' ')}`;
      })
      .join('; ');

    const name = opts.reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
    return { name, value };
  };

  // --- Permissions Policy Builder ---
  const getPermissionsHeader = (): string | null => {
    if (options.permissionsPolicy === false) return null;
    if (typeof options.permissionsPolicy !== 'object') return null; // Default is null unless explicitly set because it varies wildly
    
    return Object.entries(options.permissionsPolicy)
      .map(([feature, allowlist]) => `${feature}=${allowlist}`)
      .join(', ');
  };

  return (_req: Request, res: Response, next: NextFunction) => {
    // 1. Strict-Transport-Security
    const hsts = getHstsHeader();
    if (hsts) res.setHeader('Strict-Transport-Security', hsts);

    // 2. X-Frame-Options
    if (options.frameguard !== false) {
      res.setHeader('X-Frame-Options', (options.frameguard as string) || 'SAMEORIGIN');
    }

    // 3. X-Content-Type-Options
    if (options.noSniff !== false) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
    }

    // 4. X-DNS-Prefetch-Control
    if (options.dnsPrefetchControl !== false) {
      res.setHeader('X-DNS-Prefetch-Control', (options.dnsPrefetchControl as string) || 'off');
    }

    // 5. X-Download-Options
    if (options.ieNoOpen !== false) {
      res.setHeader('X-Download-Options', 'noopen');
    }

    // 6. X-Permitted-Cross-Domain-Policies
    if (options.permittedCrossDomainPolicies !== false) {
      res.setHeader('X-Permitted-Cross-Domain-Policies', (options.permittedCrossDomainPolicies as string) || 'none');
    }

    // 7. Referrer-Policy
    if (options.referrerPolicy !== false) {
       const policy = options.referrerPolicy === true ? 'no-referrer' : (options.referrerPolicy || 'no-referrer');
       res.setHeader('Referrer-Policy', Array.isArray(policy) ? policy.join(',') : policy);
    }

    // 8. X-XSS-Protection
    if (options.xssFilter !== false) {
      // Modern browsers ignore this, but good for legacy
      res.setHeader('X-XSS-Protection', (options.xssFilter as string) || '0');
    }

    // 9. Content-Security-Policy
    const csp = getCspHeader();
    if (csp) {
      res.setHeader(csp.name, csp.value);
    }

    // 10. Cross-Origin Embedder Policy (COEP)
    if (options.crossOriginEmbedderPolicy !== false) {
      res.setHeader('Cross-Origin-Embedder-Policy', (options.crossOriginEmbedderPolicy as string) || 'require-corp');
    }

    // 11. Cross-Origin Opener Policy (COOP)
    if (options.crossOriginOpenerPolicy !== false) {
      res.setHeader('Cross-Origin-Opener-Policy', (options.crossOriginOpenerPolicy as string) || 'same-origin');
    }

    // 12. Cross-Origin Resource Policy (CORP)
    if (options.crossOriginResourcePolicy !== false) {
      res.setHeader('Cross-Origin-Resource-Policy', (options.crossOriginResourcePolicy as string) || 'same-origin');
    }

    // 13. Permissions-Policy
    if (options.permissionsPolicy) {
      const pp = getPermissionsHeader();
      if (pp) res.setHeader('Permissions-Policy', pp);
    }

    next();
  };
}
