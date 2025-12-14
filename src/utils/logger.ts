/**
 * Default Logger Utility
 * 
 * Provides a minimal, zero-dependency console logger.
 * For production, users should inject their own logger (e.g., Winston, Pino).
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface Logger {
  debug(message: string, ...meta: unknown[]): void;
  info(message: string, ...meta: unknown[]): void;
  warn(message: string, ...meta: unknown[]): void;
  error(message: string, ...meta: unknown[]): void;
  log(level: LogLevel, message: string, ...meta: unknown[]): void;
}

/**
 * Creates a simple console logger with prefixed output.
 */
function createLogger(prefix: string = 'ZSECURE'): Logger {
  const format = (level: string, msg: string) => 
    `[${prefix}:${level.toUpperCase()}] ${new Date().toISOString()} - ${msg}`;

  return {
    debug: (msg, ...meta) => console.debug(format('debug', msg), ...meta),
    info: (msg, ...meta) => console.info(format('info', msg), ...meta),
    warn: (msg, ...meta) => console.warn(format('warn', msg), ...meta),
    error: (msg, ...meta) => console.error(format('error', msg), ...meta),
    log: (level, msg, ...meta) => {
      const fn = console[level] || console.log;
      fn(format(level, msg), ...meta);
    }
  };
}

// Default exported logger instance
export const logger: Logger = createLogger();
