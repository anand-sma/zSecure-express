import { Request, Response, NextFunction } from 'express';
import { RateLimitStore, MemoryStore, RedisStore } from './stores';
import { logger } from '../../../utils/logger';

// Optional logger hook for rate-limiter events
export type RateLimitLogger = (
  level: 'debug' | 'info' | 'warn' | 'error',
  message: string,
  meta?: Record<string, any>
) => void;

export interface RateLimitOptions {
  windowMs?: number; // Window size for time-based limits (default: 1 min)
  max?: number | ((req: Request) => number); // Max hits per window

  // Concurrency
  limitConcurrentRequests?: boolean; // Enable concurrent request limiting
  maxConcurrent?: number; // Max active requests at once

  // Slow Down
  slowDown?: {
    delayAfter: number; // Start delaying after this many requests
    delayMs: number; // Initial delay in ms
    maxDelayMs?: number; // Max delay cap
  };

  // Penalties
  abuseThreshold?: number; // Ban after X limit violations
  banTimeMs?: number; // Ban duration

  // Advanced
  keyGenerator?: (req: Request) => string;
  skip?: (req: Request) => boolean;
  store?: RateLimitStore; // Custom store
  redisClient?: any; // Shortcut to create RedisStore

  // Compliance
  standardHeaders?: boolean; // Return RateLimit-* headers
  legacyHeaders?: boolean; // Return X-RateLimit-* headers

  message?: string | object;
}

/**
 * Enterprise Multi-Layer Rate Limiter
 *
 * Features:
 * - Window-based limiting (Fixed Window)
 * - Concurrency limiting
 * - Slow-down (Throttling)
 * - Auto-banning (Jail)
 * - Distributed support (Redis)
 */
export function createRateLimitMiddleware(options: RateLimitOptions = {}) {
  const windowMs = options.windowMs || 60 * 1000;
  const max = typeof options.max === 'number' ? options.max : 100; // Default flat limit if func not provided
  const getMax = typeof options.max === 'function' ? options.max : () => max;

  const enableConcurrent = options.limitConcurrentRequests || false;
  const maxConcurrent = options.maxConcurrent || 10;

  const keyGenerator =
    options.keyGenerator ||
    ((req: Request) => {
      // Smart Key: Combining IP + User (if auth) for granular limits using "Double-Keying"
      const ip = req.ip || req.socket.remoteAddress || 'unknown';
      // @ts-expect-error - Assuming auth middleware runs before or user ID is in header
      const user = req.user?.id || req.headers['x-user-id'] || 'anon';
      return `${ip}::${user}`;
    });

  // Init Store
  let store: RateLimitStore;
  if (options.store) {
    store = options.store;
  } else if (options.redisClient) {
    store = new RedisStore(options.redisClient);
  } else {
    store = new MemoryStore(windowMs); // Pass cleanup interval
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    if (options.skip && options.skip(req)) return next();

    const key = keyGenerator(req);
    const limit = getMax(req);

    try {
      // 1. Check Concurrency (if enabled)
      if (enableConcurrent && store instanceof MemoryStore) {
        // Only supported reliably in MemoryStore for now
        const record = await store.get(key);
        if (
          record &&
          record.activeRequests &&
          record.activeRequests >= maxConcurrent
        ) {
          res
            .status(429)
            .json({ error: 'Too Many Concurrent Requests', retryAfter: 0 });
          return;
        }
      }

      // 2. Increment & Check Window
      // We assume store handles atomic increment + expiry logic
      const record = await store.increment(key, windowMs);

      // Headers
      if (options.standardHeaders !== false) {
        res.setHeader('RateLimit-Limit', limit);
        res.setHeader('RateLimit-Remaining', Math.max(0, limit - record.hits));
        res.setHeader('RateLimit-Reset', Math.ceil(record.resetTime / 1000));
      }

      // 3. Slow Down Logic (Exponential Backoff-ish)
      if (options.slowDown && record.hits > options.slowDown.delayAfter) {
        const excess = record.hits - options.slowDown.delayAfter;
        const delay = Math.min(
          excess * options.slowDown.delayMs,
          options.slowDown.maxDelayMs || 20000
        );

        // Artificial delay
        await new Promise((resolve) => setTimeout(resolve, delay));
      }

      // 4. Block Logic
      if (record.hits > limit) {
        // Auto-Scale / Ban logic could go here (Abuse Threshold)
        if (options.abuseThreshold && record.hits > limit * 2) {
          // If they are 2x over limit, count as abuse
          // Implementation of complex abuse scoring would go here
          // For now, simpler "Jail"
          if (record.hits > limit * 5) {
            await store.block(key, options.banTimeMs || 3600000);
          }
        }

        throw new Error('Rate limit exceeded');
      }

      // 5. Cleanup for Concurrency (on request finish)
      if (enableConcurrent) {
        res.on('finish', () => store.decrement(key));
        res.on('close', () => store.decrement(key));
      }

      next();
    } catch (err: any) {
      if (err.message === 'BLOCKED' || err.message === 'Rate limit exceeded') {
        const resetSec = Math.ceil((Date.now() + windowMs) / 1000); // Rough estimate if record unavailable
        res.setHeader('Retry-After', resetSec);

        return res.status(429).json(
          options.message || {
            status: 'error',
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests',
          }
        );
      }

      logger.error('Rate Limit Store Error', err);
      next(); // Fail open for store errors
    }
  };
}
