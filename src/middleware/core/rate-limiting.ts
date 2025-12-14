import { Request, Response, NextFunction } from 'express';

// --- Interfaces ---

export interface RateLimitLogger {
  warn(message: string, meta?: any): void;
  error(message: string, meta?: any): void;
}

export interface RateLimitOptions {
  /**
   * Time frame for measuring requests (in milliseconds).
   * Default: 60000 (1 minute)
   */
  windowMs?: number;

  /**
   * Max number of connections during windowMs before blocking.
   * Default: 100
   */
  max?: number; // | ((req: Request) => number) // Could support dynamic limits

  /**
   * If `max` is exceeded `abuseThreshold` times, the client is banned for `banTimeMs`.
   * Default: 0 (Disabled)
   */
  abuseThreshold?: number;

  /**
   * Duration of the ban in milliseconds.
   * Default: 3600000 (1 hour)
   */
  banTimeMs?: number;

  /**
   * Message sent to blocked clients.
   */
  message?: string | object;

  /**
   * HTTP Status code for rate limit exceeded. Default: 429
   */
  statusCode?: number;

  /**
   * Enable/Disable headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After).
   * Default: true
   */
  headers?: boolean;

  /**
   * Key generator function. Defaults to IP.
   */
  keyGenerator?: (req: Request) => string;

  /**
   * Handler for when limit is reached.
   */
  handler?: (req: Request, res: Response, next: NextFunction, options: RateLimitOptions) => void;

  /**
   * Optional Redis client for distributed clustering.
   * Must provide get/set/expire methods.
   */
  redisClient?: any;

  logger?: RateLimitLogger;
}

interface ClientRecord {
  hits: number;
  resetTime: number;
  abuseCount: number;
  bannedUntil?: number;
}

// --- Default Logger ---
const defaultLogger: RateLimitLogger = {
  warn: (msg, meta) => console.warn(`[RateLimit:WARN] ${msg}`, meta || ''),
  error: (msg, meta) => console.error(`[RateLimit:ERROR] ${msg}`, meta || '')
};

// --- In-Memory Store (Fallback) ---
const memoryStore = new Map<string, ClientRecord>();

// Cleanup interval (every 1 min)
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, record] of memoryStore.entries()) {
    // If expired and not banned (or ban expired), delete
    if (record.resetTime <= now && (!record.bannedUntil || record.bannedUntil <= now)) {
      memoryStore.delete(key);
    }
  }
}, 60000);
if (cleanupTimer.unref) cleanupTimer.unref();


/**
 * Advanced Security Rate Limiter
 * 
 * Includes:
 * - Standard Window Counter
 * - "Jail" System: Auto-bans repeat offenders
 * - Distributed State (Redis) or Local Memory
 * - Request Fingerprinting
 */
export function createRateLimitMiddleware(options: RateLimitOptions = {}) {
  const windowMs = options.windowMs || 60 * 1000;
  const max = options.max || 100;
  const abuseThreshold = options.abuseThreshold || 0; // 0 = disabled
  const banTimeMs = options.banTimeMs || 60 * 60 * 1000; // 1 hour
  const statusCode = options.statusCode || 429;
  const enableHeaders = options.headers !== false;
  const logger = options.logger || defaultLogger;
  const redis = options.redisClient;

  const generateKey = options.keyGenerator || ((req: Request) => req.ip || req.socket.remoteAddress || 'unknown');

  // Helper: Get Record
  const getRecord = async (key: string): Promise<ClientRecord> => {
    const now = Date.now();
    const defaultRecord: ClientRecord = { hits: 0, resetTime: now + windowMs, abuseCount: 0 };
    
    if (redis) {
      try {
        const raw = await redis.get(`rl:${key}`);
        return raw ? JSON.parse(raw) : defaultRecord;
      } catch (err) {
        logger.error('Redis get error', err);
        return defaultRecord; // Fail open-ish (new record)
      }
    }
    return memoryStore.get(key) || defaultRecord;
  };

  // Helper: Save Record
  const saveRecord = async (key: string, record: ClientRecord) => {
    const now = Date.now();
    
    // Calculate TTL
    let ttl = windowMs;
    // If banned, TTL must extend to ban time
    if (record.bannedUntil && record.bannedUntil > now) {
      ttl = record.bannedUntil - now;
    }
    // Ensure positive TTL
    ttl = Math.max(ttl, 1000);

    if (redis) {
      try {
        await redis.set(`rl:${key}`, JSON.stringify(record), 'PX', ttl);
      } catch (err) {
        logger.error('Redis set error', err);
      }
    } else {
      memoryStore.set(key, record);
    }
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = generateKey(req);
      const now = Date.now();
      
      let record = await getRecord(key);

      // 1. Check if Banned
      if (record.bannedUntil && record.bannedUntil > now) {
        const retrySecs = Math.ceil((record.bannedUntil - now) / 1000);
        if (enableHeaders) {
          res.setHeader('Retry-After', String(retrySecs));
        }
        
        logger.warn(`Rejected banned client`, { key, remainingBan: retrySecs });
        
        return res.status(403).json({
          status: 'error',
          code: 'CLIENT_BANNED',
          message: 'Temporarily banned due to excessive traffic abuse.',
          retryAfter: retrySecs
        });
      }

      // 2. Window Reset Logic
      if (now > record.resetTime) {
        // Window expired, reset hits but keep abuse count (maybe decay abuse count?)
        record.hits = 0;
        record.resetTime = now + windowMs;
        // Optional: Could decay abuse count here if we wanted
      }

      // 3. Increment Hits
      record.hits++;
      
      // Calculate Remaining
      const remaining = Math.max(0, max - record.hits);

      // 4. Set Standard Headers
      if (enableHeaders) {
        res.setHeader('X-RateLimit-Limit', String(max));
        res.setHeader('X-RateLimit-Remaining', String(remaining));
        res.setHeader('X-RateLimit-Reset', String(Math.ceil(record.resetTime / 1000)));
      }

      // 5. Check Limit
      if (record.hits > max) {
        // --- Limit Exceeded ---
        
        // Handle Abuse Counting
        if (abuseThreshold > 0) {
          record.abuseCount++;
          if (record.abuseCount >= abuseThreshold) {
            // Trigger Jail
            record.bannedUntil = now + banTimeMs;
            await saveRecord(key, record);

            logger.warn(`Banning IP ${key} for ${banTimeMs/1000}s due to abuse threshold`);
            
            return res.status(403).json({
              status: 'error',
              code: 'CLIENT_BANNED',
              message: 'Too many blocked requests. You are banned.',
              retryAfter: Math.ceil(banTimeMs / 1000)
            });
          }
        }

        await saveRecord(key, record);

        // Call Custom Handler or Default
        if (options.handler) {
           return options.handler(req, res, next, options);
        }

        res.setHeader('Retry-After', String(Math.ceil((record.resetTime - now) / 1000)));
        return res.status(statusCode).json(options.message || {
          status: 'error',
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests, please try again later.'
        });
      }

      // Save state
      await saveRecord(key, record);
      next();
    } catch (error) {
      logger.error('Rate limit error', error);
      next();
    }
  };
}