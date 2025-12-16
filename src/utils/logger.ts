/**
 * Enterprise Logger Utility
 * 
 * Provides a structured, zero-dependency logger with sensitive data redaction.
 * Compatible with modern observability stacks (ELK, Splunk, etc.).
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LoggerOptions {
  prefix?: string;
  json?: boolean;
  sensitiveKeys?: string[];
}

export interface Logger {
  debug(message: string, ...meta: unknown[]): void;
  info(message: string, ...meta: unknown[]): void;
  warn(message: string, ...meta: unknown[]): void;
  error(message: string, ...meta: unknown[]): void;
  log(level: LogLevel, message: string, ...meta: unknown[]): void;
}

const DEFAULT_SENSITIVE_KEYS = ['password', 'token', 'secret', 'authorization', 'cookie', 'key', 'access_token'];

/**
 * Safely stringifies objects, handling circular references and masking sensitive data.
 */
function safeStringify(obj: unknown, sensitiveKeys: string[]): string {
  const seen = new WeakSet();
  
  return JSON.stringify(obj, (key, value) => {
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        return '[Circular]';
      }
      seen.add(value);
    }
    
    if (sensitiveKeys.includes(key.toLowerCase())) {
      return '***REDACTED***';
    }
    
    return value;
  });
}

function maskData(data: unknown[], sensitiveKeys: string[]): unknown[] {
  return data.map(item => {
    if (typeof item === 'object' && item !== null) {
      try {
        return JSON.parse(safeStringify(item, sensitiveKeys));
      } catch {
        return item;
      }
    }
    return item;
  });
}

/**
 * Creates a robust logger instance.
 */
function createLogger(options: LoggerOptions = {}): Logger {
  const { 
    prefix = 'ZSECURE', 
    json = process.env.NODE_ENV === 'production',
    sensitiveKeys = DEFAULT_SENSITIVE_KEYS 
  } = options;

  const output = (level: LogLevel, msg: string, meta: unknown[]) => {
    const maskedMeta = maskData(meta, sensitiveKeys);
    
    if (json) {
      const entry = {
        timestamp: new Date().toISOString(),
        level,
        service: prefix,
        message: msg,
        meta: maskedMeta.length > 0 ? maskedMeta : undefined
      };
      console.log(JSON.stringify(entry));
    } else {
      const timestamp = new Date().toISOString();
      const metaStr = maskedMeta.length ? JSON.stringify(maskedMeta) : '';
      const color = level === 'error' ? '\x1b[31m' : level === 'warn' ? '\x1b[33m' : '\x1b[36m';
      const reset = '\x1b[0m';
      
      console.log(`${color}[${prefix}:${level.toUpperCase()}]${reset} ${timestamp} - ${msg} ${metaStr}`);
    }
  };

  return {
    debug: (msg, ...meta) => output('debug', msg, meta),
    info: (msg, ...meta) => output('info', msg, meta),
    warn: (msg, ...meta) => output('warn', msg, meta),
    error: (msg, ...meta) => output('error', msg, meta),
    log: (level, msg, ...meta) => output(level, msg, meta)
  };
}

// Default exported logger instance
export const logger: Logger = createLogger();
export { createLogger };
