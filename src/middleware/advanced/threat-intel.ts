import { Request, Response, NextFunction } from 'express';
import * as http from 'http';
import * as https from 'https';

// --- Interfaces ---

export interface ThreatIntelLogger {
  info(message: string): void;
  warn(message: string, meta?: any): void;
  error(message: string, meta?: any): void;
}

export interface ThreatScore {
  score: number;       // 0 (safe) to 100 (dangerous)
  tags: string[];      // e.g., 'tor', 'botnet', 'spam'
  source: string;      // Provider name
}

/**
 * Interface for any external Threat Intelligence Source.
 * Implement this to wrap APIs like AbuseIPDB, VirusTotal, or local DBs.
 */
export interface ThreatProvider {
  name: string;
  check(ip: string): Promise<ThreatScore | null>;
}

export interface ThreatIntelOptions {
  /**
   * Minimum score to block a request. Default: 80.
   */
  blockThreshold?: number;
  
  /**
   * List of custom providers (API wrappers, DB lookups).
   */
  providers?: ThreatProvider[];
  
  /**
   * URLs returning plain text lists of malicious IPs (one per line).
   * Middleware will fetch and cache these periodically.
   * Example: 'https://check.torproject.org/torbulkexitlist'
   */
  ipBlocklistUrls?: string[];
  
  /**
   * How often to refresh remote blocklists (in milliseconds).
   * Default: 1 hour (3600000 ms).
   */
  refreshIntervalMs?: number;

  /**
   * Cache duration for lookups in seconds. Default: 3600 (1 hour).
   */
  cacheTtlSeconds?: number;

  /**
   * Optional Redis client for distributed caching. 
   * Must implement get/set methods.
   */
  redisClient?: any;

  logger?: ThreatIntelLogger;
}

// --- Default Console Logger ---
const defaultLogger: ThreatIntelLogger = {
  info: (msg) => console.log(`[ThreatIntel] ${msg}`),
  warn: (msg, meta) => console.warn(`[ThreatIntel:WARN] ${msg}`, meta || ''),
  error: (msg, meta) => console.error(`[ThreatIntel:ERROR] ${msg}`, meta || '')
};

// --- Utilities ---

/**
 * Simple HTTP(S) GET to fetch blocklists without external libs (axios/node-fetch).
 */
function fetchList(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, (res) => {
      if (res.statusCode !== 200) {
        res.resume(); // consume to free memory
        return reject(new Error(`Failed to fetch ${url}: Status ${res.statusCode}`));
      }
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', (err) => reject(err));
    req.end();
  });
}

// --- Core Logic ---

export class ThreatIntelEngine {
  private localBlocklist: Set<string> = new Set();
  private cache: Map<string, { score: ThreatScore, expires: number }> = new Map();
  private logger: ThreatIntelLogger;
  private options: ThreatIntelOptions;

  constructor(options: ThreatIntelOptions) {
    this.options = options;
    this.logger = options.logger || defaultLogger;

    // Initialize background refresh if URLs provided
    if (this.options.ipBlocklistUrls && this.options.ipBlocklistUrls.length > 0) {
      this.refreshBlocklists();
      setInterval(() => this.refreshBlocklists(), this.options.refreshIntervalMs || 3600000).unref();
    }
  }

  private async refreshBlocklists() {
    this.logger.info('Refreshing remote blocklists...');
    const newSet = new Set<string>();
    
    for (const url of this.options.ipBlocklistUrls || []) {
      try {
        const rawText = await fetchList(url);
        const ips = rawText.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
        ips.forEach(ip => newSet.add(ip));
        this.logger.info(`Loaded ${ips.length} IPs from ${url}`);
      } catch (err: any) {
        this.logger.warn(`Failed to sync blocklist from ${url}: ${err.message}`);
      }
    }
    
    this.localBlocklist = newSet;
    this.logger.info(`Total unique malicious IPs in memory: ${this.localBlocklist.size}`);
  }

  private async getCachedScore(ip: string): Promise<ThreatScore | null> {
    const now = Date.now();
    
    // 1. Check Redis if available
    if (this.options.redisClient) {
      try {
        const cached = await this.options.redisClient.get(`threat:${ip}`);
        if (cached) return JSON.parse(cached);
      } catch (err) {
        // Fallback silently on redis error
      }
    }

    // 2. Check Memory Cache
    const local = this.cache.get(ip);
    if (local) {
      if (local.expires > now) return local.score;
      this.cache.delete(ip);
    }
    return null;
  }

  private async setCachedScore(ip: string, score: ThreatScore) {
    const ttl = (this.options.cacheTtlSeconds || 3600);
    
    // Redis
    if (this.options.redisClient) {
      try {
        await this.options.redisClient.set(`threat:${ip}`, JSON.stringify(score), 'EX', ttl);
      } catch (err) { /* ignore */ }
    }
    
    // Memory
    this.cache.set(ip, { 
      score, 
      expires: Date.now() + (ttl * 1000) 
    });

    // Memory Housekeeping (prevent infinite growth)
    if (this.cache.size > 10000) {
      const oldest = this.cache.keys().next().value;
      if (oldest) this.cache.delete(oldest); // Safe guard, remove one if exists
    }
  }

  public async evaluate(ip: string): Promise<ThreatScore> {
    // 1. Check Local Static Blocklist (Instant)
    if (this.localBlocklist.has(ip)) {
      return { score: 100, tags: ['flagged_list'], source: 'static_blocklist' };
    }

    // 2. Check Cache
    const cached = await this.getCachedScore(ip);
    if (cached) return cached;

    // 3. Query Providers
    // We aggregate scores. Since we want "aggressively defensive", we take the MAX score found.
    let maxScore = 0;
    const combinedTags: string[] = [];
    let detectedSource = 'none';

    if (this.options.providers) {
      // Run parallely for speed
      const results = await Promise.allSettled(this.options.providers.map(p => p.check(ip)));
      
      for (const res of results) {
        if (res.status === 'fulfilled' && res.value) {
          const val = res.value;
          if (val.score > maxScore) {
            maxScore = val.score;
            detectedSource = val.source;
          }
          if (val.tags) combinedTags.push(...val.tags);
        }
      }
    }

    const result: ThreatScore = {
      score: maxScore,
      tags: [...new Set(combinedTags)],
      source: detectedSource
    };

    // 4. Cache Result (only cache if we actually did a lookup)
    if (this.options.providers && this.options.providers.length > 0) {
        await this.setCachedScore(ip, result);
    }

    return result;
  }
}

/**
 * Creates the Threat Intelligence Middleware.
 * 
 * Automatically blocks IPs that exceed the configured threat threshold.
 * Integrates with external providers and static lists.
 */
export function createThreatIntelMiddleware(options: ThreatIntelOptions = {}) {
  const engine = new ThreatIntelEngine(options);
  const THRESHOLD = options.blockThreshold || 80;

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const ip = (req.ip || req.socket.remoteAddress || 'unknown') as string;

      // Skip invalid or local IPs (optional optimization)
      if (ip === '127.0.0.1' || ip === '::1') return next();

      const threat = await engine.evaluate(ip);

      if (threat.score >= THRESHOLD) {
        const logger = options.logger || defaultLogger;
        logger.warn(`Threat Intelligence Block: IP ${ip} scored ${threat.score} (${threat.source})`, { tags: threat.tags });

        return res.status(403).json({
          status: 'error',
          code: 'SECURITY_THREAT_DETECTED',
          message: 'Access denied due to poor reputation.',
          request_id: Date.now() // Reference for support
        });
      }

      next();
    } catch (error) {
      // Fail open to ensure availability
      (options.logger || defaultLogger).error('Error in Threat Intel middleware', error);
      next();
    }
  };
}
