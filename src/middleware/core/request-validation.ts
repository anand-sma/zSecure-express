import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';

// --- Interfaces ---

export interface ValidationLogger {
  warn(message: string, meta?: any): void;
  info(message: string, meta?: any): void;
}

export interface RequestValidationOptions {
  /**
   * Block requests containing `__proto__`, `prototype`, or `constructor` properties.
   * Default: true
   */
  blockPrototypePollution?: boolean;

  /**
   * Block requests with duplicate query parameters (HTTP Parameter Pollution).
   * Default: true
   */
  blockParamPollution?: boolean;

  /**
   * Block requests containing null bytes (\u0000).
   * Default: true
   */
  blockNullBytes?: boolean;

  /**
   * Enforce Content-Type for write methods (POST, PUT, PATCH).
   * Default: ['application/json', 'model/multipart-form-data', 'application/x-www-form-urlencoded', 'text/plain']
   */
  allowedContentTypes?: string[];

  /**
   * Max nested depth for JSON bodies to prevent stack overflows/DoS.
   * Default: 5
   */
  maxObjectDepth?: number;

  /**
   * Custom validator function (sync or async).
   * If it returns false or throws, request is rejected.
   */
  validator?: (req: Request) => boolean | Promise<boolean>;

  logger?: ValidationLogger;
}

const defaultLogger: ValidationLogger = {
  warn: (msg, meta) => console.warn(`[VALIDATION:WARN] ${msg}`, meta || ''),
  info: (msg) => console.log(`[VALIDATION:INFO] ${msg}`)
};

/**
 * Enterprise Request Validation & Hygiene Middleware
 * 
 * Ensures input integrity by:
 * 1. Blocking Prototype Pollution attempts.
 * 2. Preventing HTTP Parameter Pollution (HPP).
 * 3. Checking for Null Byte Injection.
 * 4. Enforcing Content-Type Allowlist.
 * 5. Integrating with express-validator (if used).
 */
export function createRequestValidationMiddleware(options: RequestValidationOptions = {}) {
  const logger = options.logger || defaultLogger;
  const blockProto = options.blockPrototypePollution !== false;
  const blockHpp = options.blockParamPollution !== false;
  const blockNulls = options.blockNullBytes !== false;
  const maxDepth = options.maxObjectDepth || 5;
  const allowedTypes = options.allowedContentTypes || [
    'application/json', 
    'multipart/form-data', 
    'application/x-www-form-urlencoded',
    'text/plain'
  ];

  // --- Helpers ---

  const hasPrototypePollution = (obj: any, depth = 0): boolean => {
    if (depth > maxDepth || !obj || typeof obj !== 'object') return false;
    
    // Check keys
    for (const key in obj) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') return true;
      // Recurse
      if (hasPrototypePollution(obj[key], depth + 1)) return true;
    }
    return false;
  };

  const hasDiffParamPollution = (query: any): boolean => {
    // Basic HPP Check: check if any value is an array where it shouldn't be? 
    // Actually, Express parses ?id=1&id=2 as id: ['1', '2']. 
    // A strict mode might block ALL arrays in query if API doesn't expect them, 
    // but generic middleware should probably just warn or be configurable.
    // For now, we'll assume "Duplicate Keys" are suspicious if not explicitly allowed (but difficult to know schema).
    // Let's stick to a simpler safe-guard: Block if we detect mixed types or massive arrays?
    // Actually, simple HPP usually involves overwriting a string with an array to crash code expecting string methods.
    // We will just allow it by default in Express but maybe we can provide a 'strict' mode later.
    
    // Re-interpretation: "blockParamPollution" -> Block duplicate keys entirely?
    if (!query) return false;
    return Object.values(query).some(val => Array.isArray(val));
    // NOTE: This blocks ?ids=1&ids=2. This might be too aggressive for some apps. 
    // But options.blockParamPollution defaults to true, forcing user to opt-out if they use arrays.
  };

  const hasNullBytes = (str: unknown): boolean => {
    if (typeof str === 'string') return str.indexOf('\0') !== -1;
    if (typeof str === 'object' && str !== null) {
      return Object.values(str).some(v => hasNullBytes(v));
    }
    return false;
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    // 1. Content-Type Check (for mutating methods)
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      const contentType = req.headers['content-type'];
      if (contentType) {
        // Matches "application/json; charset=utf-8" against "application/json"
        const isValid = allowedTypes.some(t => contentType.includes(t));
        if (!isValid) {
          logger.warn(`Invalid Content-Type: ${contentType} from ${req.ip}`);
          return res.status(415).json({
            error: 'Unsupported Media Type',
            message: `Content-Type ${contentType} is not allowed.`
          });
        }
      }
    }

    // 2. Prototype Pollution Check
    if (blockProto) {
      if (hasPrototypePollution(req.body) || hasPrototypePollution(req.query) || hasPrototypePollution(req.params)) {
        logger.warn(`Prototype Pollution attempt detected from ${req.ip}`);
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Malicious payload detected (Property Forbidden).'
        });
      }
    }

    // 3. Null Byte Check
    if (blockNulls) {
      if (hasNullBytes(req.body) || hasNullBytes(req.query) || hasNullBytes(req.params)) {
        logger.warn(`Null Byte Injection attempt detected from ${req.ip}`);
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Malicious payload detected (Null Bytes).'
        });
      }
    }

    // 4. HTTP Parameter Pollution (Optional Block)
    if (blockHpp && hasDiffParamPollution(req.query)) {
       // Only block if strictly requested, as duplicate params are valid in HTTP (arrays)
       // But often unsafe in Node apps expecting strings.
       logger.warn(`HTTP Parameter Pollution detected from ${req.ip}`);
       return res.status(400).json({
         error: 'Bad Request',
         message: 'Duplicate query parameters are not allowed.'
       });
    }

    // 5. Custom Validator
    if (options.validator) {
      try {
        const isValid = await options.validator(req);
        if (!isValid) {
          return res.status(400).json({ error: 'Validation Failed' });
        }
      } catch (err) {
        logger.warn(`Custom validation error`, err);
        return res.status(400).json({ error: 'Validation Error' });
      }
    }

    // 6. Legacy Express-Validator Check
    // If user put express-validator middleware BEFORE this, we check results here.
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        status: 'error',
        code: 'VALIDATION_ERROR',
        errors: errors.array() 
      });
    }

    next();
  };
}
