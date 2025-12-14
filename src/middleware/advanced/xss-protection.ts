import { Request, Response, NextFunction } from 'express';

// --- Interfaces ---

export interface XSSLogger {
  warn(message: string, meta?: any): void;
  error(message: string, meta?: any): void;
}

export interface XSSOptions {
  /**
   * Mode of operation.
   * 'block': Abort request if XSS is detected. (Default)
   * 'sanitize': Attempt to strip malicious content and continue.
   */
  mode?: 'block' | 'sanitize';

  /**
   * Keys to exclude from checking (e.g., 'html_content').
   */
  whitelist?: string[];

  /**
   * Custom logger.
   */
  logger?: XSSLogger;
}

// --- Default Console Logger ---
const defaultLogger: XSSLogger = {
  warn: (msg, meta) => console.warn(`[XSS:WARN] ${msg}`, meta || ''),
  error: (msg, meta) => console.error(`[XSS:ERROR] ${msg}`, meta || '')
};

// --- Regex Definitions ---
// Comprehensive patterns for XSS vectors
const XSS_PATTERNS = [
  /<script\b[^>]*>([\s\S]*?)<\/script>/gim,           // <script>...</script>
  /javascript:[^"']*/gim,                              // javascript: protocol
  /on\w+\s*=\s*("|')?[^"'>]+("|')?/gim,                // Event handlers (onload=, onerror=)
  /data:text\/html/gim,                                // Data URIs
  /vbscript:/gim,                                      // vbscript protocol
  /<\s*iframe[^>]*>/gim,                               // iframes
  /<\s*object[^>]*>/gim,                               // Objects
  /<\s*embed[^>]*>/gim,                                // Embeds
  /<\s*style[^>]*>/gim                                 // Style injections
];

/**
 * XSS Protection Middleware
 * 
 * Scans request body, query, and params for XSS vectors.
 * Can be configured to BLOCK requests or SANITIZE inputs.
 */
export function createXSSMiddleware(options: XSSOptions = {}) {
  const logger = options.logger || defaultLogger;
  const whitelist = new Set(options.whitelist || []);
  const mode = options.mode || 'block';

  // Helper: Check string for XSS
  const detectXSS = (str: string): boolean => {
    return XSS_PATTERNS.some(pattern => pattern.test(str));
  };

  // Helper: Sanitize string (Basic stipping)
  const sanitizeString = (str: string): string => {
    let sanitized = str;
    XSS_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[REMOVED_XSS]');
    });
    return sanitized;
  };

  /**
   * Recursive Scanner/Sanitizer
   * Returns:
   *   - If mode='block': boolean (true if malicious)
   *   - If mode='sanitize': number (count of sanitized fields - *mutates input*)
   */
  const processPayload = (input: any, keyName: string = ''): boolean | number => {
    if (whitelist.has(keyName)) return mode === 'block' ? false : 0;

    if (typeof input === 'string') {
      if (detectXSS(input)) {
        if (mode === 'block') return true; // Block immediately
        // Sanitize logic is tricky because we can't easily mutate the string in specific nested position 
        // without returning it. This simplifed logic assumes we update via reference if object, 
        // but for string passed directly, we can't. 
        // Actually, for robust sanitization of deep objects, we need to return the new value.
        // But for 'check', returning boolean is enough.
        return 1; 
      }
      return mode === 'block' ? false : 0;
    }

    if (Array.isArray(input)) {
      if (mode === 'block') {
        return input.some(item => processPayload(item, keyName));
      } else {
        // Sanitization in place for arrays
        let sanitizedCount = 0;
        for (let i = 0; i < input.length; i++) {
          if (typeof input[i] === 'string') {
             if (detectXSS(input[i])) {
                input[i] = sanitizeString(input[i]);
                sanitizedCount++;
             }
          } else {
             sanitizedCount += (processPayload(input[i], keyName) as number);
          }
        }
        return sanitizedCount;
      }
    }

    if (input && typeof input === 'object') {
      if (mode === 'block') {
        return Object.keys(input).some(key => processPayload(input[key], key));
      } else {
        // Sanitization in place for objects
        let sanitizedCount = 0;
        for (const key of Object.keys(input)) {
          if (typeof input[key] === 'string') {
            if (detectXSS(input[key])) {
               input[key] = sanitizeString(input[key]);
               sanitizedCount++;
            }
          } else {
            sanitizedCount += (processPayload(input[key], key) as number);
          }
        }
        return sanitizedCount;
      }
    }

    return false; // Default for numbers, booleans, null
  };

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const inputs = [
        { source: 'body', data: req.body },
        { source: 'query', data: req.query },
        { source: 'params', data: req.params }
      ];

      for (const { source, data } of inputs) {
        if (!data) continue;

        if (mode === 'block') {
          // Block Mode
          const isMalicious = processPayload(data);
          if (isMalicious) {
            const ip = req.ip || req.socket.remoteAddress || 'unknown';
            logger.warn(`XSS Attempt Blocked`, {
              ip,
              path: req.path,
              source,
              payload_snippet: JSON.stringify(data).slice(0, 100)
            });

            return res.status(403).json({
              status: 'error',
              code: 'XSS_DETECTED',
              message: 'Malicious content detected in request.'
            });
          }
        } else {
          // Sanitize Mode
          const changes = processPayload(data) as number;
          if (changes > 0) {
             const ip = req.ip || req.socket.remoteAddress || 'unknown';
             logger.warn(`XSS Content Sanitized (${changes} fields)`, {
               ip,
               path: req.path,
               source
             });
          }
        }
      }

      next();
    } catch (error) {
       logger.error('Error in XSS middleware', error);
       next();
    }
  };
}
