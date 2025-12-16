import { Request, Response, NextFunction } from 'express';
import { validationResult, Result, ValidationError } from 'express-validator';
import { logger } from '../../utils/logger';

// --- Interfaces ---

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
   * Default: ['application/json', 'multipart/form-data', 'application/x-www-form-urlencoded', 'text/plain']
   */
  allowedContentTypes?: string[];

  /**
   * Max nested depth for JSON bodies to prevent stack overflows/DoS.
   * Default: 5
   */
  maxObjectDepth?: number;

  /**
   * Max elements in an array to prevent DoS.
   * Default: 50
   */
  maxArraySize?: number;

  /**
   * Custom validator function (sync or async).
   * If it returns false or throws, request is rejected.
   */
  validator?: (req: Request) => boolean | Promise<boolean>;
}

/**
 * Enterprise Request Validation & Hygiene Middleware
 * 
 * Ensures input integrity by:
 * 1. Blocking Prototype Pollution attempts.
 * 2. Preventing HTTP Parameter Pollution (HPP).
 * 3. Checking for Null Byte Injection.
 * 4. Enforcing Content-Type Allowlist.
 * 5. Integrating with express-validator (if used).
 * 6. Limiting recursion depth and array sizes.
 */
export function createRequestValidationMiddleware(options: RequestValidationOptions = {}) {
  const blockProto = options.blockPrototypePollution !== false;
  const blockHpp = options.blockParamPollution !== false;
  const blockNulls = options.blockNullBytes !== false;
  const maxDepth = options.maxObjectDepth || 5;
  const maxArraySize = options.maxArraySize || 50;
  
  const allowedTypes = options.allowedContentTypes || [
    'application/json', 
    'multipart/form-data', 
    'application/x-www-form-urlencoded',
    'text/plain'
  ];

  // --- Helpers ---

  const hasPrototypePollution = (obj: any, depth = 0): boolean => {
    if (!obj || typeof obj !== 'object') return false;
    if (depth > maxDepth) return false; // Stop recursing, let depth check handle it separately if we wanted, but logic below handles depth.
    
    // Check keys
    for (const key in obj) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') return true;
      // Recurse
      if (hasPrototypePollution(obj[key], depth + 1)) return true;
    }
    return false;
  };

  const checkStructureLimits = (obj: any, depth = 0): { valid: boolean, reason?: string } => {
     if (depth > maxDepth) return { valid: false, reason: 'Max Depth Exceeded' };
     
     if (Array.isArray(obj)) {
         if (obj.length > maxArraySize) return { valid: false, reason: 'Max Array Size Exceeded' };
         for (const item of obj) {
             const res = checkStructureLimits(item, depth + 1);
             if (!res.valid) return res;
         }
     } else if (obj && typeof obj === 'object') {
         for (const key in obj) {
             const res = checkStructureLimits(obj[key], depth + 1);
             if (!res.valid) return res;
         }
     }
     return { valid: true };
  };

  const hasDiffParamPollution = (query: any): boolean => {
    // Basic HPP Check: Block duplicates (arrays) in query if strict mode
    // Express parses ?id=1&id=2 as id: ['1', '2']
    if (!query) return false;
    return Object.values(query).some(val => Array.isArray(val));
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

    // 2. Data Structure Limits (DoS Prevention)
    // Only check body as params/query are usually small strings
    if (req.body && typeof req.body === 'object') {
        const structureCheck = checkStructureLimits(req.body);
        if (!structureCheck.valid) {
            logger.warn(`DoS Attempt prevented (${structureCheck.reason}) from ${req.ip}`);
             return res.status(400).json({
                error: 'Bad Request',
                message: `Payload too complex (${structureCheck.reason})`
            });
        }
    }

    // 3. Prototype Pollution Check
    if (blockProto) {
      if (hasPrototypePollution(req.body) || hasPrototypePollution(req.query) || hasPrototypePollution(req.params)) {
        logger.warn(`Prototype Pollution attempt detected from ${req.ip}`);
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Malicious payload detected (Property Forbidden).'
        });
      }
    }

    // 4. Null Byte Check
    if (blockNulls) {
      if (hasNullBytes(req.body) || hasNullBytes(req.query) || hasNullBytes(req.params)) {
        logger.warn(`Null Byte Injection attempt detected from ${req.ip}`);
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Malicious payload detected (Null Bytes).'
        });
      }
    }

    // 5. HTTP Parameter Pollution (Optional Block)
    if (blockHpp && hasDiffParamPollution(req.query)) {
       logger.warn(`HTTP Parameter Pollution detected from ${req.ip}`);
       // Standard Enterprise response: 400 Bad Request
       return res.status(400).json({
         error: 'Bad Request',
         message: 'Duplicate query parameters are not allowed.'
       });
    }

    // 6. Custom Validator
    if (options.validator) {
      try {
        const isValid = await options.validator(req);
        if (!isValid) {
          return res.status(400).json({ error: 'Custom Validation Failed' });
        }
      } catch (err: any) {
        logger.warn(`Custom validation error`, { message: err.message });
        return res.status(400).json({ error: 'Validation Error' });
      }
    }

    // 7. Legacy Express-Validator Check
    // If user put express-validator middleware BEFORE this, we check results here.
    const errors: Result<ValidationError> = validationResult(req);
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
