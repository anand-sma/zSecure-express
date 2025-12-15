import { Request, Response, NextFunction } from 'express';

// ============================================================================
// Interfaces
// ============================================================================

export interface AnomalyLogger {
  log(level: string, message: string): void;
  warn(message: string): void;
  error(message: string, meta?: unknown): void;
}

const defaultLogger: AnomalyLogger = {
  log: (level, msg) => console.log(`[ANOMALY:${level.toUpperCase()}] ${msg}`),
  warn: (msg) => console.warn(`[ANOMALY:WARN] ${msg}`),
  error: (msg, meta) => console.error(`[ANOMALY:ERROR] ${msg}`, meta || '')
};

export interface AnomalyOptions {
  threshold?: number;   // Base Z-Score threshold. Default: 3.0 (99.7% confidence deviation)
  learningRate?: number; // Alpha for EMA (0.0 to 1.0). Default: 0.1 (Slow learning, stable)
  whitelist?: string[];
  redisClient?: any;
  logger?: AnomalyLogger;
}

/**
 * The Brain: Statistical Profile of a Client
 */
export interface ClientProfile {
  firstSeen: number;
  lastSeen: number;
  requestCount: number;
  
  // Statistical Models (Exponential Moving Averages)
  interArrival: {
    mean: number;     // Avg time between requests (ms)
    variance: number; // Stability of rhythm
  };
  
  payload: {
    mean: number;     // Avg content-length
    variance: number;
  };
  
  errorRate: number;  // Moving average of 4xx/5xx (0.0 - 1.0)
  
  // Anomaly Counter (for persistent blocking)
  violationScore: number;
}

// ============================================================================
// Statistical Math Engine (Zero Dependency)
// ============================================================================

const Stats = {
  /**
   * Updates an Exponential Moving Average
   * @param oldMean Current average
   * @param newValue New data point
   * @param alpha Learning rate (0 < alpha < 1)
   */
  updateMean: (oldMean: number, newValue: number, alpha: number): number => {
    return (alpha * newValue) + ((1 - alpha) * oldMean);
  },

  /**
   * Updates Moving Variance (Welford's algorithm adaptation for EMA)
   * Var_new = (1-alpha) * (Var_old + alpha * (x - Mean_old)^2)
   */
  updateVariance: (oldVar: number, oldMean: number, newValue: number, alpha: number): number => {
    const diff = newValue - oldMean;
    return ((1 - alpha) * (oldVar + (alpha * diff * diff)));
  },

  /**
   * Calculates Z-Score (Standardized Metric)
   * How many standard deviations is the value away from the mean?
   */
  calcZScore: (value: number, mean: number, variance: number): number => {
    // Enforce minimum variance to prevent division by zero AND to handle perfectly stable bots
    // If variance is 0, any deviation is infinite Z-score. 
    // We assume a minimum standard deviation of 1ms or 1 byte to be practical.
    const effectiveVariance = Math.max(variance, 1); 
    const stdDev = Math.sqrt(effectiveVariance);
    return Math.abs(value - mean) / stdDev;
  }
};

// ============================================================================
// State Management
// ============================================================================

const memoryStore = new Map<string, ClientProfile>();
const CLEANUP_INTERVAL = 600 * 1000;

// Cleanup timer
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, state] of memoryStore.entries()) {
    if (now - state.lastSeen > CLEANUP_INTERVAL) {
      memoryStore.delete(key);
    }
  }
}, CLEANUP_INTERVAL);

if (cleanupTimer.unref) cleanupTimer.unref();

// ============================================================================
// Middleware Implementation
// ============================================================================

export function createAnomalyDetectionMiddleware(options: AnomalyOptions = {}) {
  const THRESHOLD = options.threshold || 3.0; // Standard Deviation limit
  const ALPHA = options.learningRate || 0.1;  // Learning speed
  const MIN_SAMPLES = 10;                     // Min requests needed before judging
  const redis = options.redisClient;
  const logger = options.logger || defaultLogger;

  // --- Store Helpers ---
  const getProfile = async (ip: string): Promise<ClientProfile> => {
    const now = Date.now();
    const defaultProfile: ClientProfile = {
      firstSeen: now,
      lastSeen: now,
      requestCount: 0,
      interArrival: { mean: 1000, variance: 0 }, // Init with 1 sec expectation
      payload: { mean: 0, variance: 0 },
      errorRate: 0,
      violationScore: 0
    };

    if (redis) {
      try {
        const raw = await redis.get(`ai_anomaly:${ip}`);
        return raw ? JSON.parse(raw) : defaultProfile;
      } catch (err) { return defaultProfile; }
    }
    return memoryStore.get(ip) || defaultProfile;
  };

  const saveProfile = async (ip: string, profile: ClientProfile) => {
    if (redis) {
      try {
        await redis.set(`ai_anomaly:${ip}`, JSON.stringify(profile), 'EX', 86400);
      } catch (e) { /* silent fail */ }
    } else {
      memoryStore.set(ip, profile);
    }
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const ip = (req.ip || req.socket.remoteAddress || 'unknown') as string;
      if (options.whitelist?.includes(ip)) return next();

      const profile = await getProfile(ip);
      const now = Date.now();
      const interArrival = now - profile.lastSeen;
      const payloadSize = parseInt(req.headers['content-length'] || '0', 10);

      // --- 1. INFERENCE PHASE (Judge the request) ---
      let anomalyScore = 0;
      let reasons: string[] = [];

      // Only judge if we have enough history (Confidence)
      if (profile.requestCount > MIN_SAMPLES) {
        
        // A. Rhythm Anomaly (Burst Detection)
        // If they are suddenly 100x faster than their normal
        const rhythmZ = Stats.calcZScore(interArrival, profile.interArrival.mean, profile.interArrival.variance);
        


        // We only care if they are much FASTER (smaller interArrival) than normal
        // Z-Score is typically symmetric, but for security, being SLOWER is fine.
        if (interArrival < profile.interArrival.mean && rhythmZ > THRESHOLD) {
           anomalyScore += rhythmZ; 
           reasons.push(`Abnormal Rhythm (Z: ${rhythmZ.toFixed(2)})`);
        }

        // B. Payload Anomaly
        // If payload is much LARGER than normal
        if (payloadSize > 0) {
            const payloadZ = Stats.calcZScore(payloadSize, profile.payload.mean, profile.payload.variance);
            if (payloadSize > profile.payload.mean && payloadZ > THRESHOLD) {
                anomalyScore += (payloadZ * 0.5); // Weighted lower than rhythm
                reasons.push(`Abnormal Payload (Z: ${payloadZ.toFixed(2)})`);
            }
        }
      }

      // --- 2. LEARNING PHASE (Update the brain) ---
      
      // Update Rhythm Model (only if not a complete anomaly, to avoid poisoning the well?)
      // Actually, we use weighted averages, so anomalies naturally pull the average but slowly.
      // However, for pure attacks, we might pause learning.
      if (anomalyScore < (THRESHOLD * 2)) {
          // Update means first
          const oldTimeMean = profile.interArrival.mean;
          profile.interArrival.mean = Stats.updateMean(oldTimeMean, interArrival, ALPHA);
          profile.interArrival.variance = Stats.updateVariance(profile.interArrival.variance, oldTimeMean, interArrival, ALPHA);

          const oldSizeMean = profile.payload.mean;
          profile.payload.mean = Stats.updateMean(oldSizeMean, payloadSize, ALPHA);
          profile.payload.variance = Stats.updateVariance(profile.payload.variance, oldSizeMean, payloadSize, ALPHA);
      }

      // Update counters
      profile.lastSeen = now;
      profile.requestCount++;

      // --- 3. DECISION PHASE ---
      
      // Hook into Response to track errors (Post-Request Learning)

      
      // Note: We can't easily intercept 'write' for status code in all Express versions safely without proxy
      // Use 'on-headers' or 'finish' event is safer for stats.
      res.on('finish', () => {
         const isError = res.statusCode >= 400;
         // Update Error Rate (0 or 1)
         profile.errorRate = Stats.updateMean(profile.errorRate, isError ? 1 : 0, ALPHA);
         saveProfile(ip, profile).catch(() => {});
      });

      // BLOCKING DECISION
      if (anomalyScore > (THRESHOLD * 1.5)) {
          profile.violationScore++;
          logger.warn(`AI Detection: Blocking IP ${ip}. Reasons: ${reasons.join(', ')}`);
          
          await saveProfile(ip, profile);
          
          res.status(403).json({
              error: 'Traffic Anomaly',
              message: 'Your request pattern is highly irregular.'
          });
          return; // Stop execution
      }

      // Warning
      if (anomalyScore > THRESHOLD) {
          logger.log('info', `Suspicious activity from ${ip}: ${reasons.join(', ')}`);
      }

      // Save state before next() to ensure sequential consistency for fast bursts?
      // In high-concurrency Node, 'await' here might slow things down. 
      // We rely on 'finish' listener for save usually, but for burst detection, 
      // we need the updated 'lastSeen' immediately available for the next req.
      await saveProfile(ip, profile);
      
      next();

    } catch (err) {
      logger.error('Anomaly AI Error', err);
      next();
    }
  };
}
