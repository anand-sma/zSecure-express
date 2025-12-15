import { Request, Response, NextFunction } from 'express';

// Export interfaces for package usage
export interface SQLInjectionLogger {
  warn(message: string, meta?: any): void;
  error(message: string, meta?: any): void;
}

export interface SQLInjectionOptions {
  /**
   * List of specific keys to ignore in the request body/query/params.
   * Useful for fields that naturally contain SQL-like syntax (e.g., search queries, code snippets).
   */
  whitelist?: string[];
  
  /**
   * Custom logger instance. Defaults to console.
   */
  logger?: SQLInjectionLogger;
  
  /**
   * Aggression level for detection.
   * 'high': Checks for broad patterns (e.g. UNION, OR 1=1). Higher false positives.
   * 'medium': Checks for common attack vectors. Balanced. (Default)
   * 'low': Minimal checks for obvious attacks (DROP TABLE, etc).
   */
  level?: 'low' | 'medium' | 'high';
}

const defaultLogger: SQLInjectionLogger = {
  warn: (msg, meta) => console.warn(`[SQLi:WARN] ${msg}`, meta || ''),
  error: (msg, meta) => console.error(`[SQLi:ERROR] ${msg}`, meta || '')
};

/**
 * Aggressive SQL Injection Defense Middleware
 * 
 * Deeply scans request body, query params, and route params for malicious SQL patterns.
 * Supports recursive object scanning and configurable aggression levels.
 */
export function createSQLInjectionMiddleware(options: SQLInjectionOptions = {}) {
  const logger = options.logger || defaultLogger;
  const whitelist = new Set(options.whitelist || []);
  const level = options.level || 'medium';

  // --- Regex Definitions ---

  // Level 'low': Obvious destructive commands and comments
  const lowRiskPatterns = [
    /(%27)|(')|(--)|(%23)|(#)/i,           // Single quote, double dash, hash
    /(\/\*)|(\*\/)/i,                            // Comment blocks
    /(;)\s*(DROP|ALTER|CREATE|DELETE|UPDATE|INSERT)/i // Chained destructive commands
  ];

  // Level 'medium': Common injection vectors (UNION, boolean based)
  const mediumRiskPatterns = [
    ...lowRiskPatterns,
    /(UNION\s+SELECT)/i,
    /(UNION\s+ALL\s+SELECT)/i,
    /(\s+OR\s+)(\d+)(\s*=\s*)(\d+)/i,            // OR 1=1 patterns
    /(\s+OR\s+)(')(.*)(')(\s*=\s*)(')(.*)(')/i,  // OR 'a'='a' patterns
    /(EXEC\s*\()/i,                              // Stored procedure execution
    /(Xp_cmdshell)/i                             // SQL Server remote command
  ];

  // Level 'high': Broad keywords and function calls (Risky for false positives)
  const highRiskPatterns = [
    ...mediumRiskPatterns,
    /(SELECT|UPDATE|DELETE|INSERT|TRUNCATE|FROM|WHERE|JOIN|INTO|TABLE|DATABASE)/i, // Structural keywords
    /(@@version|@@spid)/i,                       // System variables
    /(WAITFOR\s+DELAY)/i                         // Time-based blind injection
  ];

  const patterns = 
    level === 'high' ? highRiskPatterns :
    level === 'low' ? lowRiskPatterns :
    mediumRiskPatterns;


  // --- Helper Functions ---

  const hasSQLInjection = (value: string): boolean => {
    if (typeof value !== 'string') return false;
    // Normalize slightly to catch obfuscation (optional, can be expanded)
    return patterns.some(pattern => pattern.test(value));
  };

  /**
   * Recursively scans an object for SQL injection patterns.
   * returns TRUE if injection is detected.
   */
  const scan = (input: any, keyName: string = ''): boolean => {
    // 1. Skip whitelisted keys
    if (whitelist.has(keyName)) return false;

    // 2. Check Strings
    if (typeof input === 'string') {
      return hasSQLInjection(input);
    }

    // 3. Check Arrays
    if (Array.isArray(input)) {
      return input.some(item => scan(item, keyName));
    }

    // 4. Check Objects (Recursively)
    if (input && typeof input === 'object') {
      return Object.keys(input).some(key => scan(input[key], key));
    }

    return false;
  };

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const inputs = [
        { source: 'body', data: req.body },
        { source: 'query', data: req.query },
        { source: 'params', data: req.params }
      ];

      for (const { source, data } of inputs) {
        if (data && scan(data)) {
          const ip = req.ip || req.socket.remoteAddress || 'unknown';
          
          logger.warn(`SQL Injection Detected`, {
            ip,
            path: req.path,
            source,
            payload: JSON.stringify(data).slice(0, 200) // Log snippet of payload
          });

          return res.status(403).json({
            status: 'error',
            code: 'SQL_INJECTION_DETECTED',
            message: 'Malicious request payload detected. Blocked.'
          });
        }
      }

      next();
    } catch (error) {
      logger.error('Error in SQL injection middleware', error);
      // Fail safely? In high security, maybe block. For general use, fail open.
      // We'll fail open to avoid breaking the app on internal errors.
      next();
    }
  };
}
