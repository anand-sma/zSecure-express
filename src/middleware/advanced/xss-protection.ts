import { Request, Response, NextFunction } from 'express';
import { logger } from '../../utils/logger';

// --- Interfaces ---

export interface XSSOptions {
  /**
   * Mode of operation.
   * 'block': Abort request if XSS is detected. (Default)
   * 'sanitize': Escape dangerous characters to HTML entities.
   */
  mode?: 'block' | 'sanitize';

  /**
   * Keys to exclude from checking (e.g., 'html_content').
   */
  whitelist?: string[];
}

// --- Regex Definitions ---
// Characters that trigger encoding/blocking
// < > " ' / `
const DANGEROUS_CHARS = /[<>"'/`]/g;

// Patterns that almost certainly indicate an attack (for blocking mode)
const BLOCK_PATTERNS = [
  /javascript:/i,
  /vbscript:/i,
  /data:text\/html/i,
  /onload\s*=/i,
  /onerror\s*=/i,
  /onclick\s*=/i,
  /<script/i,
  /<iframe/i,
  /<object/i,
  /<embed/i
];

/**
 * XSS Protection Middleware
 * 
 * Protects against Reflected and Stored XSS by either:
 * 1. Blocking requests containing dangerous XSS vectors.
 * 2. Sanitizing inputs by encoding HTML entities (Input Hygiene).
 */
export function createXSSMiddleware(options: XSSOptions = {}) {
  const whitelist = new Set(options.whitelist || []);
  const mode = options.mode || 'block';

  // Helper: Encode HTML Entities
  const encode = (str: string): string => {
    return str.replace(DANGEROUS_CHARS, (char) => {
      switch (char) {
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '"': return '&quot;';
        case "'": return '&#x27;';
        case '/': return '&#x2F;';
        case '`': return '&#96;';
        default: return char;
      }
    });
  };

  // Helper: Detect Blocking Checks
  const hasAttackVector = (str: string): boolean => {
    // 1. Check for dangerous characters if in strict mode? 
    // Actually blocking every < or > is too aggressive for some apps, but standard for high security JSON apis.
    // Let's use the explicit block patterns for less false positives, 
    // OR if tight security, block any <script tag.
    return BLOCK_PATTERNS.some(p => p.test(str));
  };

  /**
   * Recursive Processor
   */
  const processPayload = (input: any, keyName: string = ''): boolean | number => {
    if (whitelist.has(keyName)) return mode === 'block' ? false : 0;

    if (typeof input === 'string') {
      if (mode === 'block') {
        if (hasAttackVector(input)) return true;
      } else {
        // Sanitize: Encode dangerous chars
        // We can't mutate primitives passed by value here, done in parent loop
        // But for return value count, we verify if it needs changing
        if (DANGEROUS_CHARS.test(input)) return 1;
      }
      return false; 
    }

    if (Array.isArray(input)) {
      if (mode === 'block') {
         return input.some(item => processPayload(item, keyName));
      } else {
         let count = 0;
         for (let i = 0; i < input.length; i++) {
            const item = input[i];
            if (typeof item === 'string') {
               if (DANGEROUS_CHARS.test(item)) {
                  input[i] = encode(item);
                  count++;
               }
            } else {
               count += (processPayload(item, keyName) as number);
            }
         }
         return count;
      }
    }

    if (input && typeof input === 'object') {
       if (mode === 'block') {
          return Object.keys(input).some(key => processPayload(input[key], key));
       } else {
          let count = 0;
          for (const key of Object.keys(input)) {
             const val = input[key];
             if (typeof val === 'string') {
                if (DANGEROUS_CHARS.test(val)) {
                   input[key] = encode(val);
                   count++;
                }
             } else {
                count += (processPayload(val, key) as number);
             }
          }
          return count;
       }
    }

    return false;
  };

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Inputs to check
      const inputSources = [
          { name: 'body', data: req.body },
          { name: 'query', data: req.query },
          { name: 'params', data: req.params }
      ];

      for (const { name, data } of inputSources) {
        if (!data) continue;

        if (mode === 'block') {
           const isMalicious = processPayload(data);
           if (isMalicious) {
              logger.warn(`XSS Blocked in ${name}`, { ip: req.ip, path: req.path });
              return res.status(403).json({
                 status: 'error',
                 code: 'SECURITY_VIOLATION',
                 message: 'Malicious content detected (XSS).'
              });
           }
        } else {
           const sanitizedCount = processPayload(data);
           if (sanitizedCount) {
             // We modified req.body/query in place
             // Just log info
             logger.info(`XSS Sanitized ${sanitizedCount} fields in ${name}`, { ip: req.ip });
           }
        }
      }

      next();
    } catch (error: any) {
       logger.error('XSS Middleware Error', error);
       next();
    }
  };
}
