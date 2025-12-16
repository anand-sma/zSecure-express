import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

// --- Interfaces ---

export interface HelmetOptions {
  /**
   * Content Security Policy (CSP) options.
   */
  contentSecurityPolicy?:
    | {
        useDefaults?: boolean;
        directives?: Record<string, string | string[]>;
        reportOnly?: boolean;
        reportUri?: string;
      }
    | boolean;

  /**
   * Cross-Origin Embedder Policy (COEP).
   * Default: 'require-corp'
   */
  crossOriginEmbedderPolicy?: boolean | 'require-corp' | 'credentialless';

  /**
   * Cross-Origin Opener Policy (COOP).
   * Default: 'same-origin'
   */
  crossOriginOpenerPolicy?:
    | boolean
    | 'same-origin'
    | 'same-origin-allow-popups'
    | 'unsafe-none';

  /**
   * Cross-Origin Resource Policy (CORP).
   * Default: 'same-origin'
   */
  crossOriginResourcePolicy?:
    | boolean
    | 'same-origin'
    | 'same-site'
    | 'cross-origin';

  /**
   * Origin-Agent-Cluster.
   * Default: '?1' (true)
   */
  originAgentCluster?: boolean;

  /**
   * X-DNS-Prefetch-Control.
   * Default: 'off'
   */
  dnsPrefetchControl?: boolean | 'off' | 'on';

  /**
   * X-Frame-Options.
   * Default: 'DENY'
   */
  frameguard?: boolean | 'DENY' | 'SAMEORIGIN';

  /**
   * Strict-Transport-Security (HSTS).
   * Default: max-age=31536000; includeSubDomains; preload
   */
  hsts?:
    | {
        maxAge?: number;
        includeSubDomains?: boolean;
        preload?: boolean;
      }
    | boolean;

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
  permittedCrossDomainPolicies?:
    | boolean
    | 'none'
    | 'master-only'
    | 'by-content-type'
    | 'all';

  /**
   * Referrer-Policy.
   * Default: 'strict-origin-when-cross-origin'
   */
  referrerPolicy?: boolean | string | string[];

  /**
   * X-XSS-Protection.
   * Default: '1; mode=block'
   */
  xssFilter?: boolean | '0' | '1' | '1; mode=block';

  /**
   * Permissions-Policy.
   * Default: geolocation=(), microphone=(), camera=()
   */
  permissionsPolicy?: Record<string, string> | boolean;

  /**
   * Feature-Policy (Legacy).
   * Default: synced with Permissions-Policy defaults.
   */
  featurePolicy?: Record<string, string> | boolean;

  /**
   * Server Header Obfuscation.
   * Default: 'Apache' (Fake) or null to remove.
   */
  hidePoweredBy?: boolean | string;

  /**
   * Cache-Control headers for no-caching (Security best practice for APIs).
   * Default: true
   */
  noCache?: boolean;
}

/**
 * Enterprise Security Headers Middleware
 *
 * A robust, Zero-Trust implementation of security headers.
 * Protects against XSS, Clickjacking, MIME-sniffing, and ensures SSL enforcement.
 * Includes dynamic CSP with Nonce support.
 */
export function createHelmetMiddleware(options: HelmetOptions = {}) {
  // --- Generators ---

  const generateNonce = (): string => {
    return crypto.randomBytes(16).toString('base64');
  };

  return (_req: Request, res: Response, next: NextFunction) => {
    const nonce = generateNonce();
    // Expose nonce to views/other middlewares
    res.locals.nonce = nonce;

    // Inject Traceability Header
    res.setHeader('X-Request-ID', nonce);

    // 1. Strict-Transport-Security (HSTS)
    if (options.hsts !== false) {
      const opts = typeof options.hsts === 'object' ? options.hsts : {};
      // Enterprise Standard: 1 Year + SubDomains + Preload
      const maxAge = opts.maxAge || 31536000;
      let header = `max-age=${maxAge}`;
      if (opts.includeSubDomains !== false) header += '; includeSubDomains';
      if (opts.preload !== false) header += '; preload'; // Default to preload for max security
      res.setHeader('Strict-Transport-Security', header);
    }

    // 2. X-Frame-Options
    if (options.frameguard !== false) {
      res.setHeader(
        'X-Frame-Options',
        (options.frameguard as string) || 'DENY'
      );
    }

    // 3. X-Content-Type-Options
    if (options.noSniff !== false) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
    }

    // 4. X-DNS-Prefetch-Control
    if (options.dnsPrefetchControl !== false) {
      res.setHeader(
        'X-DNS-Prefetch-Control',
        (options.dnsPrefetchControl as string) || 'off'
      );
    }

    // 5. X-Download-Options
    if (options.ieNoOpen !== false) {
      res.setHeader('X-Download-Options', 'noopen');
    }

    // 6. X-Permitted-Cross-Domain-Policies
    if (options.permittedCrossDomainPolicies !== false) {
      res.setHeader(
        'X-Permitted-Cross-Domain-Policies',
        (options.permittedCrossDomainPolicies as string) || 'none'
      );
    }

    // 7. Referrer-Policy
    if (options.referrerPolicy !== false) {
      let policy = options.referrerPolicy;
      if (policy === true || policy === undefined || policy === null) {
        policy = 'strict-origin-when-cross-origin';
      }
      const headerVal = Array.isArray(policy)
        ? policy.join(',')
        : String(policy);
      res.setHeader('Referrer-Policy', headerVal);
    }

    // 8. X-XSS-Protection
    if (options.xssFilter !== false) {
      res.setHeader(
        'X-XSS-Protection',
        (options.xssFilter as string) || '1; mode=block'
      );
    }

    // 9. Cross-Origin Embedder Policy (COEP)
    if (options.crossOriginEmbedderPolicy !== false) {
      res.setHeader(
        'Cross-Origin-Embedder-Policy',
        (options.crossOriginEmbedderPolicy as string) || 'require-corp'
      );
    }

    // 10. Cross-Origin Opener Policy (COOP)
    if (options.crossOriginOpenerPolicy !== false) {
      res.setHeader(
        'Cross-Origin-Opener-Policy',
        (options.crossOriginOpenerPolicy as string) || 'same-origin'
      );
    }

    // 11. Cross-Origin Resource Policy (CORP)
    if (options.crossOriginResourcePolicy !== false) {
      res.setHeader(
        'Cross-Origin-Resource-Policy',
        (options.crossOriginResourcePolicy as string) || 'same-origin'
      );
    }

    // 12. Origin-Agent-Cluster
    if (options.originAgentCluster !== false) {
      res.setHeader('Origin-Agent-Cluster', '?1');
    }

    // 13. Permissions-Policy
    if (options.permissionsPolicy !== false) {
      const defaults = {
        geolocation: '()',
        microphone: '()',
        camera: '()',
        payment: '()',
        usb: '()',
      };

      const configured =
        typeof options.permissionsPolicy === 'object'
          ? options.permissionsPolicy
          : {};
      // Merge defaults with config
      const finalPolicy = { ...defaults, ...configured };

      const headerVal = Object.entries(finalPolicy)
        .map(([k, v]) => `${k}=${v}`)
        .join(', ');

      res.setHeader('Permissions-Policy', headerVal);
    }

    // 14. Feature-Policy (Legacy Support)
    if (options.featurePolicy !== false) {
      const defaults = {
        geolocation: "'none'",
        microphone: "'none'",
        camera: "'none'",
      };
      const configured =
        typeof options.featurePolicy === 'object' ? options.featurePolicy : {};
      const finalPolicy = { ...defaults, ...configured };

      const headerVal = Object.entries(finalPolicy)
        .map(([k, v]) => `${k} ${v}`)
        .join('; ');

      res.setHeader('Feature-Policy', headerVal);
    }

    // 15. Server Obfuscation
    res.removeHeader('X-Powered-By');
    if (options.hidePoweredBy !== false) {
      // Lie about the server to confuse scanners
      const serverName =
        typeof options.hidePoweredBy === 'string'
          ? options.hidePoweredBy
          : 'Apache';
      res.setHeader('Server', serverName);
    }

    // 16. Cache Optimization (No-Cache for security)
    if (options.noCache !== false) {
      res.setHeader(
        'Cache-Control',
        'no-store, no-cache, must-revalidate, proxy-revalidate'
      );
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.setHeader('Surrogate-Control', 'no-store');
    }

    // 17. Content-Security-Policy (Dynamic)
    if (options.contentSecurityPolicy !== false) {
      const opts =
        typeof options.contentSecurityPolicy === 'object'
          ? options.contentSecurityPolicy
          : {};

      // Defaults: Zero-Trust Strict
      const baseDirectives: Record<string, string[]> = {
        'default-src': ["'self'"],
        'base-uri': ["'self'"],
        'font-src': ["'self'", 'https:', 'data:'],
        'form-action': ["'self'"],
        'frame-ancestors': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'object-src': ["'none'"],
        // Nonce is critical for script safety
        'script-src': ["'self'", `'nonce-${nonce}'`],
        'script-src-attr': ["'none'"],
        'style-src': ["'self'", 'https:', `'nonce-${nonce}'`], // Allow inline styles with nonce too
        'upgrade-insecure-requests': [],
      };

      // Merge user directives
      if (!opts.useDefaults && opts.useDefaults !== undefined) {
        // If useDefaults is explicitly false, start empty
        Object.keys(baseDirectives).forEach((k) => delete baseDirectives[k]);
      }

      const mergedDirectives = { ...baseDirectives };

      if (opts.directives) {
        Object.entries(opts.directives).forEach(([key, val]) => {
          const defaults = mergedDirectives[key] || [];
          const additions = Array.isArray(val) ? val : [val];
          mergedDirectives[key] = [...new Set([...defaults, ...additions])];
        });
      }

      // Add report URI if configured
      if (opts.reportUri) {
        mergedDirectives['report-uri'] = [opts.reportUri];
        mergedDirectives['report-to'] = ['csp-endpoint']; // Modern reporting
      }

      // Inject any dynamic sources from middleware locals
      // e.g. res.locals.cspScripts = ['https://trusted.analytics.com']
      if (res.locals.cspScripts && Array.isArray(res.locals.cspScripts)) {
        mergedDirectives['script-src'].push(...res.locals.cspScripts);
      }

      const cspString = Object.entries(mergedDirectives)
        .map(([key, vals]) => {
          if (vals.length === 0) return key;
          return `${key} ${vals.join(' ')}`;
        })
        .join('; ');

      const headerName = opts.reportOnly
        ? 'Content-Security-Policy-Report-Only'
        : 'Content-Security-Policy';
      res.setHeader(headerName, cspString);

      // Report-To Header for modern reporting groups
      if (opts.reportUri) {
        const reportTo = {
          group: 'csp-endpoint',
          max_age: 10886400,
          endpoints: [{ url: opts.reportUri }],
        };
        res.setHeader('Report-To', JSON.stringify(reportTo));
      }
    }

    next();
  };
}
