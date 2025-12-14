import { Request, Response, NextFunction } from 'express';

// --- Interfaces ---

export interface CorsLogger {
  warn(message: string, meta?: any): void;
  info(message: string, meta?: any): void;
}

export type StaticOrigin = boolean | string | RegExp | (string | RegExp)[];

export type CustomOriginCallback = (
  requestOrigin: string | undefined,
  callback: (err: Error | null, allow: boolean) => void
) => void;

export interface CorsOptions {
  /**
   * Configures the Access-Control-Allow-Origin CORS header.
   * - `boolean`: set to `true` to reflect request origin (use caution), `false` to disable CORS.
   * - `string`: set to a specific origin (e.g., 'https://trusted.com') or '*' (all).
   * - `RegExp`: set to a regular expression pattern.
   * - `Array`: set to an array of valid origins.
   * - `Function`: Custom logic.
   * Default: `false` (CORS disabled/strict).
   */
  origin?: StaticOrigin | CustomOriginCallback;

  /**
   * Configures the Access-Control-Allow-Methods CORS header.
   * Default: 'GET,HEAD,PUT,PATCH,POST,DELETE'
   */
  methods?: string | string[];

  /**
   * Configures the Access-Control-Allow-Headers CORS header.
   * Default: reflect request headers.
   */
  allowedHeaders?: string | string[];

  /**
   * Configures the Access-Control-Expose-Headers CORS header.
   */
  exposedHeaders?: string | string[];

  /**
   * Configures the Access-Control-Allow-Credentials CORS header.
   * Set to true to pass the header, otherwise it is omitted.
   */
  credentials?: boolean;

  /**
   * Configures the Access-Control-Max-Age CORS header.
   * Number of seconds to cache preflight responses.
   */
  maxAge?: number;

  /**
   * If true, sends a 204 response for OPTIONS requests immediately.
   * Default: true
   */
  preflightContinue?: boolean;

  /**
   * If true, returns status 403 if the origin is not allowed.
   * If false, it simply doesn't add CORS headers (browser will block content access).
   * Default: false
   */
  blockOnForbidden?: boolean;

  /**
   * Success status for OPTIONS requests. Legacy browsers might choke on 204.
   * Default: 204
   */
  optionsSuccessStatus?: number;

  logger?: CorsLogger;
}

const defaultLogger: CorsLogger = {
  warn: (msg) => console.warn(`[CORS:WARN] ${msg}`),
  info: (msg) => console.log(`[CORS:INFO] ${msg}`)
};

/**
 * Enterprise-grade CORS Middleware
 * 
 * Provides strict control over Cross-Origin Resource Sharing.
 * Fully configurable to support complex origin policies, regex matching,
 * and preflight caching.
 */
export function createCorsMiddleware(options: CorsOptions = {}) {
  const logger = options.logger || defaultLogger;
  const defaults = {
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    optionsSuccessStatus: 204,
    blockOnForbidden: false
  };

  const isOriginAllowed = (origin: string | undefined, allowedOrigin: StaticOrigin): boolean => {
    if (Array.isArray(allowedOrigin)) {
      return allowedOrigin.some(o => isOriginAllowed(origin, o));
    }
    if (typeof allowedOrigin === 'string') {
      return allowedOrigin === '*' || origin === allowedOrigin;
    }
    if (allowedOrigin instanceof RegExp) {
      return !!origin && allowedOrigin.test(origin);
    }
    if (typeof allowedOrigin === 'boolean') {
      return allowedOrigin;
    }
    return false;
  };

  const configureOrigin = (req: Request, callback: (err: Error | null, allow: boolean) => void) => {
    const requestOrigin = req.headers.origin;
    const { origin } = options;

    if (origin === undefined || origin === false) {
      // Disable CORS
      return callback(null, false);
    }

    if (origin === true) {
      // Reflect origin (Caution: check security implication if credentials=true)
      return callback(null, true);
    }

    if (typeof origin === 'function') {
      (origin as CustomOriginCallback)(requestOrigin, callback);
    } else {
      // If we are strictly checking, and no origin header is present:
      // - Server-to-server requests often lack origin.
      // - Same-origin requests often lack origin.
      // - It is usually safe to allow them (allow: true) because they aren't CORS.
      // However, if we want to be paranoid, we could block. Standard CORS middleware allows them.
      if (!requestOrigin) return callback(null, true); 
      
      callback(null, isOriginAllowed(requestOrigin, origin as StaticOrigin));
    }
  };

  return (req: Request, res: Response, next: NextFunction) => {
    configureOrigin(req, (err, allow) => {
      if (err) {
        logger.warn(`Error validating origin`, err);
        return next(err);
      }

      const requestOrigin = req.headers.origin;

      if (allow && requestOrigin) {
        // Set Allowed Origin
        res.setHeader('Access-Control-Allow-Origin', requestOrigin);
        res.setHeader('Vary', 'Origin'); // Important for caching proxies
      } else if (!allow && options.blockOnForbidden && requestOrigin) {
         // Aggressive blocking mode
         const ip = req.ip || req.socket.remoteAddress;
         logger.warn(`CORS Blocked: Origin ${requestOrigin} from IP ${ip}`);
         return res.status(403).json({
           status: 'error',
           code: 'CORS_FORBIDDEN',
           message: 'Cross-Origin Request Blocked: Origin not allowed.'
         });
      }

      // If just not allowed, but not blocked, we simply do NOT set the headers.
      // Browser will see missing A-C-A-Origin and reject the payload.

      if (allow) {
        // --- Methods ---
        const methods = options.methods || defaults.methods;
        res.setHeader('Access-Control-Allow-Methods', Array.isArray(methods) ? methods.join(',') : methods);

        // --- Headers (Allowed) ---
        let allowedHeaders = options.allowedHeaders;
        if (!allowedHeaders) {
          // Reflect request headers if not specified (common convenience)
          allowedHeaders = req.headers['access-control-request-headers'];
        }
        if (allowedHeaders) {
          res.setHeader('Access-Control-Allow-Headers', Array.isArray(allowedHeaders) ? allowedHeaders.join(',') : allowedHeaders);
        }

        // --- Headers (Exposed) ---
        if (options.exposedHeaders) {
          res.setHeader('Access-Control-Expose-Headers', Array.isArray(options.exposedHeaders) ? options.exposedHeaders.join(',') : options.exposedHeaders);
        }

        // --- Credentials ---
        if (options.credentials === true) {
          res.setHeader('Access-Control-Allow-Credentials', 'true');
        }

        // --- Max Age ---
        if (options.maxAge && typeof options.maxAge === 'number') {
          res.setHeader('Access-Control-Max-Age', options.maxAge.toString());
        }
      }

      // Handle Preflight
      if (req.method === 'OPTIONS') {
        const successStatus = options.optionsSuccessStatus || defaults.optionsSuccessStatus;
        if (options.preflightContinue) {
            return next();
        } else {
            // Send status (typically 204) and Content-Length 0
            res.status(successStatus);
            res.setHeader('Content-Length', '0');
            return res.end();
        }
      }

      next();
    });
  };
}
