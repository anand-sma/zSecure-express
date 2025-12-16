import { Request, Response, NextFunction } from 'express';
import { logger } from '../../utils/logger';

// ============================================================================
// Interfaces
// ============================================================================

export interface AnomalyOptions {
  threshold?: number;   // Base anomaly score threshold (0-100). Default: 80
  learningRate?: number; // Alpha for EMA (0.0 to 1.0). Default: 0.1
  whitelist?: string[];
  redisClient?: any;
  enableNLP?: boolean; // Enable payload analysis
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

  pathDepth: {
    mean: number;
    variance: number;
  };
  
  errorRate: number;  // Moving average of 4xx/5xx (0.0 - 1.0)
  violationScore: number;
}

export interface AnomalyLogger {
    warn(message: string, meta?: any): void;
    error(message: string, meta?: any): void;
    info(message: string, meta?: any): void;
}

// ============================================================================
// Statistical Math Engine
// ============================================================================

const Stats = {
  updateMean: (oldMean: number, newValue: number, alpha: number): number => {
    return (alpha * newValue) + ((1 - alpha) * oldMean);
  },

  updateVariance: (oldVar: number, oldMean: number, newValue: number, alpha: number): number => {
    const diff = newValue - oldMean;
    return ((1 - alpha) * (oldVar + (alpha * diff * diff)));
  },

  calcZScore: (value: number, mean: number, variance: number): number => {
    const effectiveVariance = Math.max(variance, 0.1); 
    const stdDev = Math.sqrt(effectiveVariance);
    return Math.abs(value - mean) / stdDev;
  },

  /**
   * Simplified Isolation Forest Logic (Outlier Detection)
   * Scores how "deep" a value is in a random tree. 
   * Rare values are isolated quickly (short path).
   * For this stateless version, we approximate "isolation" via deviation from population norms.
   */
  calcIsolationScore: (features: number[], norms: number[][]): number => {
      // features: [interArrival, payloadSize, pathDepth, errorRate]
      // In a real IF, we'd traverse trees. Here we calculate Mahalanobis-like distance
      // as a proxy for "how easy it is to isolate this point".
      let anomalySum = 0;
      features.forEach((val, idx) => {
          const [mean, stdDev] = norms[idx]; // [mean, stdDev]
          if (stdDev > 0) {
              const z = Math.abs(val - mean) / stdDev;
              anomalySum += z;
          }
      });
      // Normalize to 0-100 range roughly
      return Math.min(100, anomalySum * 10);
  }
};

// ============================================================================
// NLP Engine (Payload Analysis)
// ============================================================================

const NLP = {
    /**
     * Analyzes text for malicious intent markers (SQLi, XSS, Shell).
     * Returns a probability score (0-1).
     */
    analyzePayload: (text: string): number => {
        if (!text || text.length < 5) return 0;
        
        let score = 0;
        
        // 1. Keyword density
        const keywords = ['select', 'union', 'drop', 'script', 'eval', 'exec', 'system', 'cmd'];
        const lower = text.toLowerCase();
        
        let keywordCount = 0;
        keywords.forEach(k => { if (lower.includes(k)) keywordCount++; });
        if (keywordCount > 2) score += 0.4;

        // 2. Entropy / Randomness (Obfuscation detection)
        // High non-alphanumeric ratio often implies obfuscated code or binary data injection
        const special = (text.match(/[^a-zA-Z0-9\s]/g) || []).length;
        const ratio = special / text.length;
        if (ratio > 0.4) score += 0.3;

        // 3. Length outliers (handled by stats, but very long strings are suspicious in short fields)
        if (text.length > 1000) score += 0.1;

        return Math.min(1, score);
    }
};

// ============================================================================
// Middleware Implementation
// ============================================================================

const memoryStore = new Map<string, ClientProfile>();
const CLEANUP_INTERVAL = 600 * 1000;

// Cleanup
setInterval(() => {
  const now = Date.now();
  for (const [key, state] of memoryStore.entries()) {
    if (now - state.lastSeen > CLEANUP_INTERVAL) memoryStore.delete(key);
  }
}, CLEANUP_INTERVAL).unref();

export function createAnomalyDetectionMiddleware(options: AnomalyOptions = {}) {
  const BLOCK_THRESHOLD = options.threshold || 80;
  const ALPHA = options.learningRate || 0.1;
  const MIN_SAMPLES = 5;
  const redis = options.redisClient;

  // Global "Population" Norms (Approximated/Hardcoded for now, could be learned)
  // [Mean, StdDev] for [InterArrival, PayloadSize, PathDepth, ErrorRate]
  const POPULATION_NORMS = [
      [2000, 2000], // InterArrival: Expect 2s avg
      [500, 1000],  // Payload: Expect small
      [3, 2],       // Path Depth: Expect 3 segments
      [0.05, 0.2]   // Error Rate: Expect 5%
  ];

  const getProfile = async (ip: string): Promise<ClientProfile> => {
    const now = Date.now();
    const defaultProfile: ClientProfile = {
      firstSeen: now,
      lastSeen: now,
      requestCount: 0,
      interArrival: { mean: 2000, variance: 0 },
      payload: { mean: 0, variance: 0 },
      pathDepth: { mean: 2, variance: 0 },
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
      } catch (e) { /* silent */ }
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
      
      // Feature Extraction
      const interArrival = now - profile.lastSeen;
      const payloadSize = parseInt(req.headers['content-length'] || '0', 10);
      const pathDepth = req.path.split('/').filter(Boolean).length;
      
      // --- 1. NLP Analysis (Zero-Day Payload Detection) ---
      let nlpScore = 0;
      if (options.enableNLP && req.method !== 'GET') {
          // Check body keys if JSON
          if (req.body && typeof req.body === 'object') {
              const bodyStr = JSON.stringify(req.body);
              nlpScore = NLP.analyzePayload(bodyStr);
          }
      }

      // --- 2. Statistical Inference (Isolation Score) ---
      let anomalyScore = 0;
      const reasons: string[] = [];

      if (profile.requestCount > MIN_SAMPLES) {
          // Feature Vector for this request
          // Note: Error rate is laggy (previous requests), so we use profile value
          // We treat interArrival < 100ms as highly suspicious (bot)
          if (interArrival < 100) anomalyScore += 20;

          // Personal Deviation (Z-Score against Self)
          const burstZ = Stats.calcZScore(interArrival, profile.interArrival.mean, profile.interArrival.variance);
          if (burstZ > 3 && interArrival < profile.interArrival.mean) {
              anomalyScore += 15;
              reasons.push('Burst Traffic');
          }

          // Population Deviation (Isolation Outlier)
          const isoScore = Stats.calcIsolationScore(
              [interArrival, payloadSize, pathDepth, profile.errorRate],
              POPULATION_NORMS
          );
          
          anomalyScore += (isoScore * 0.5); // Weighted
          if (isoScore > 50) reasons.push('Behavioral Outlier');
          
          // Add NLP Score (High confidence)
          if (nlpScore > 0.5) {
              anomalyScore += (nlpScore * 50);
              reasons.push('Malicious Payload Pattern');
          }
      }

      // --- 3. Learning (Update Profile) ---
      // Only learn if not blocked, to avoid poisoning model with attack data
      if (anomalyScore < BLOCK_THRESHOLD) {
          profile.interArrival.mean = Stats.updateMean(profile.interArrival.mean, interArrival, ALPHA);
          profile.interArrival.variance = Stats.updateVariance(profile.interArrival.variance, profile.interArrival.mean, interArrival, ALPHA);

          profile.payload.mean = Stats.updateMean(profile.payload.mean, payloadSize, ALPHA);
          profile.payload.variance = Stats.updateVariance(profile.payload.variance, profile.payload.mean, payloadSize, ALPHA);
          
          profile.pathDepth.mean = Stats.updateMean(profile.pathDepth.mean, pathDepth, ALPHA);
      }

      profile.lastSeen = now;
      profile.requestCount++;

      // Post-Request Learning Hook
      res.on('finish', () => {
          const isError = res.statusCode >= 400;
          profile.errorRate = Stats.updateMean(profile.errorRate, isError ? 1 : 0, ALPHA);
          saveProfile(ip, profile).catch(() => {});
      });
      
      // --- 4. Decision ---
      if (anomalyScore >= BLOCK_THRESHOLD) {
          profile.violationScore += 20;
          logger.warn(`Anomaly Block: IP ${ip} Score ${anomalyScore.toFixed(0)}`, { reasons });
          
          await saveProfile(ip, profile);
          
          return res.status(403).json({
              error: 'Behavioral Anomaly',
              message: 'Request blocked by adaptive defense.'
          });
      }

      await saveProfile(ip, profile);
      next();

    } catch (err) {
      logger.error('Anomaly Engine Error', err);
      next();
    }
  };
}
