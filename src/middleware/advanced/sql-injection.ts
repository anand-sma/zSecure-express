import { Request, Response, NextFunction } from 'express';
import { logger } from '../../utils/logger';

// --- Interfaces ---

export interface SQLInjectionOptions {
  /**
   * List of specific keys to ignore in the request body/query/params.
   */
  whitelist?: string[];
  
  /**
   * Aggression level for detection.
   * 'high': Checks for broad patterns. Higher false positives.
   * 'medium': Checks for common attack vectors. Balanced. (Default)
   * 'low': Minimal checks for obvious attacks.
   */
  level?: 'low' | 'medium' | 'high';

  /**
   * Check for NoSQL (MongoDB) injection operators (e.g. $gt, $ne).
   * Default: true
   */
  detectNoSQL?: boolean;
}

/**
 * Aggressive SQL & NoSQL Injection Defense Middleware
 * 
 * Deeply scans request body, query params, and route params for malicious SQL and NoSQL patterns.
 * Supports recursive object scanning.
 */
export function createSQLInjectionMiddleware(options: SQLInjectionOptions = {}) {
  const whitelist = new Set(options.whitelist || []);
  const level = options.level || 'medium';
  const detectNoSQL = options.detectNoSQL !== false;

  // --- SQL Regex Definitions ---

  const lowRiskSQL = [
    /(%27)|(')|(--)|(%23)|(#)/i,                      // Comments/Quotes
    /(\/\*)|(\*\/)/i,                                 // Block Comments
    /(;)\s*(DROP|ALTER|CREATE|DELETE|UPDATE|INSERT)/i // Chained commands
  ];

  const mediumRiskSQL = [
    ...lowRiskSQL,
    /(UNION\s+SELECT)/i,
    /(UNION\s+ALL\s+SELECT)/i,
    /(\s+OR\s+)(\d+)(\s*=\s*)(\d+)/i,            // OR 1=1
    /(\s+OR\s+)(')(.*)(')(\s*=\s*)(')(.*)(')/i,  // OR 'a'='a'
    /(EXEC\s*\()/i,                              // Stored Proc
    /(Xp_cmdshell)/i                             // SQL Server
  ];

  const highRiskSQL = [
    ...mediumRiskSQL,
    /(SELECT|UPDATE|DELETE|INSERT|TRUNCATE|FROM|WHERE|JOIN|INTO|TABLE|DATABASE)/i,
    /(@@version|@@spid)/i,
    /(WAITFOR\s+DELAY)/i
  ];

  const sqlPatterns = 
    level === 'high' ? highRiskSQL :
    level === 'low' ? lowRiskSQL :
    mediumRiskSQL;

  // --- NoSQL Definitions ---
  // Common Mongo Operators that shouldn't be in user input usually
  const noSqlOperators = [
     '$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', 
     '$or', '$and', '$not', '$nor', '$exists', '$type', '$mod', 
     '$regex', '$text', '$where', '$elemMatch'
  ];

  // --- Helpers ---

  const hasSQLInjection = (value: string): boolean => {
    if (typeof value !== 'string') return false;
    return sqlPatterns.some(pattern => pattern.test(value));
  };

  const hasNoSQLInjection = (key: string): boolean => {
     // If a key in an object starts with $, it's often a NoSQL operator injection 
     // (e.g. { "username": { "$ne": null } })
     return noSqlOperators.includes(key);
  };

  const scan = (input: any, keyName: string = ''): boolean => {
    if (whitelist.has(keyName)) return false;

    // 1. Check NoSQL Keys (if object)
    if (detectNoSQL && typeof input === 'object' && input !== null && !Array.isArray(input)) {
        const keys = Object.keys(input);
        for (const key of keys) {
            if (key.startsWith('$') && hasNoSQLInjection(key)) return true;
        }
    }

    // 2. Check Strings (SQL)
    if (typeof input === 'string') {
      return hasSQLInjection(input);
    }

    // 3. Recurse Arrays
    if (Array.isArray(input)) {
      return input.some(item => scan(item, keyName));
    }

    // 4. Recurse Objects
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
           
           logger.warn(`Injection Detected (${source})`, {
             ip,
             path: req.path, // Use path instead of url to avoid logging query string twice if not careful
             source,
             payload_snippet: JSON.stringify(data).slice(0, 150)
           });

           return res.status(403).json({
             status: 'error',
             code: 'INJECTION_DETECTED',
             message: 'Malicious payload detected (SQL/NoSQL).'
           });
        }
      }

      next();
    } catch (error) {
      logger.error('Error in Injection Middleware', error);
      next();
    }
  };
}
