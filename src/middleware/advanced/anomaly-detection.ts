import { Request, Response, NextFunction } from 'express';

// Export Logger interface
export interface AnomalyLogger {
  log(level: string, message: string): void;
  warn(message: string): void;
  error(message: string, meta?: any): void;
}

// Default Console Logger
const defaultLogger: AnomalyLogger = {
  log: (level, msg) => console.log(`[ANOMALY:${level.toUpperCase()}] ${msg}`),
  warn: (msg) => console.warn(`[ANOMALY:WARN] ${msg}`),
  error: (msg, meta) => console.error(`[ANOMALY:ERROR] ${msg}`, meta || '')
};



export interface AnomalyOptions {
  threshold?: number;   // Score to trigger block. Default: 100
  decayRate?: number;   // Points regenerated per second. Default: 1
  whitelist?: string[]; // IPs to bypass
  checkHeaders?: boolean;
  redisClient?: any;    // Optional external store (e.g., ioredis instance)
  logger?: AnomalyLogger; // Optional custom logger
}

export interface ClientState {
  score: number;
  lastSeen: number;
  lastPath: string;
  violationCount: number;
}

// In-memory store for client behavioral data (fallback)
const memoryStore = new Map<string, ClientState>();

// Periodic cleanup of stale entries (every 10 minutes) for memory store
const CLEANUP_INTERVAL = 600 * 1000;
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, state] of memoryStore.entries()) {
    if (now - state.lastSeen > CLEANUP_INTERVAL) {
      memoryStore.delete(key);
    }
  }
}, CLEANUP_INTERVAL);

// Ensure timer doesn't prevent process exit
if (cleanupTimer.unref) {
  cleanupTimer.unref();
}

/**
 * Anomaly Detection Middleware
 * 
 * Uses a heuristic scoring system to identify suspicious traffic patterns.
 * Supports clustering via Redis if provided in options, otherwise defaults to in-memory.
 */
export function createAnomalyDetectionMiddleware(options: AnomalyOptions = {}) {
  const BLOCK_THRESHOLD = options.threshold || 100;
  const DECAY_RATE = options.decayRate || 2; // Recovers 2 points per second
  const MIN_INTERVAL_MS = 100; // Burst detection threshold
  const redis = options.redisClient;
  const logger = options.logger || defaultLogger;

  // Helper to get state from Store (Redis or Memory)
  const getState = async (ip: string): Promise<ClientState> => {
    const now = Date.now();
    const defaultState: ClientState = { score: 0, lastSeen: now, lastPath: '', violationCount: 0 };

    if (redis) {
      try {
        const raw = await redis.get(`anomaly:${ip}`);
        return raw ? JSON.parse(raw) : defaultState;
      } catch (err) {
        logger.error('Redis error in anomaly detection, falling back to empty state', err);
        return defaultState;
      }
    }
    return memoryStore.get(ip) || defaultState;
  };

  // Helper to save state to Store
  const saveState = async (ip: string, state: ClientState) => {
    if (redis) {
        try {
            // Expire after 24 hours to prevent infinite growth
            await redis.set(`anomaly:${ip}`, JSON.stringify(state), 'EX', 86400); 
        } catch (err) {
            logger.error('Redis set error', err);
        }
    } else {
        memoryStore.set(ip, state);
    }
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const ip = (req.ip || req.socket.remoteAddress || 'unknown') as string;

      // Skip whitelisted IPs
      if (options.whitelist?.includes(ip)) {
        return next();
      }

      const now = Date.now();
      const state = await getState(ip);

      // 1. Calculate Score Decay
      const timeDeltaMs = now - state.lastSeen;
      // If we just fetched from Redis and it's old, decay might be large
      // Only decay if time has passed
      if (timeDeltaMs > 0) {
          const decayAmount = Math.floor((timeDeltaMs / 1000) * DECAY_RATE);
          state.score = Math.max(0, state.score - decayAmount);
      }

      // --- Scoring LOGIC ---
      let requestScore = 0;

      // A. Burst/Rate Anomaly
      if (timeDeltaMs < MIN_INTERVAL_MS && timeDeltaMs >= 0) {
        if (req.path === state.lastPath) {
          requestScore += 10;
        } else {
          requestScore += 2;
        }
      }

      // B. Header Anomalies
      if (!req.get('User-Agent')) {
        requestScore += 20;
      }
      
      if (JSON.stringify(req.headers).length > 8192) {
        requestScore += 30;
      }

      // C. Method Anomalies
      const standardMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
      if (!standardMethods.includes(req.method.toUpperCase())) {
        requestScore += 50;
      }

      // D. URL/Path Anomalies
      if (req.url.length > 2048) {
        requestScore += 25;
      }

      // Update State
      state.score += requestScore;
      state.lastSeen = now;
      state.lastPath = req.path;

      // Trigger Save (async, don't await blocking unless strict consistency needed)
      // For blocking logic below, we use local `state` copy which is fresh.
      // We will await saveState before responding if we block, or just fire-and-forget if we pass?
      // Better to await to ensure consistency in race conditions, though slight perf penalty.
      await saveState(ip, state);

      // --- Enforcement ---
      if (state.score >= BLOCK_THRESHOLD) {
        state.violationCount++;
        await saveState(ip, state); // Update violation count
        
        const logLevel = state.violationCount > 5 ? 'error' : 'warn';
        logger.log(logLevel, `Anomaly Detected: Blocking IP ${ip} due to score ${state.score}. Pathway: ${req.path}`);

        return res.status(403).json({
          status: 'error',
          code: 'TRAFFIC_ANOMALY',
          message: 'Unusual traffic patterns detected. Your request has been blocked.'
        });
      }
      
      // Warning threshold (80%)
      if (state.score >= (BLOCK_THRESHOLD * 0.8)) {
        logger.warn(`Anomaly Warning: IP ${ip} score is high (${state.score}).`);
      }

      next();
    } catch (error) {
      logger.error('Error in anomaly detection middleware', error);
      next();
    }
  };
}
