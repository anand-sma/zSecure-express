import { Request, Response, NextFunction } from 'express';
import * as http from 'http';
import * as https from 'https';
import { logger } from '../../utils/logger';

// --- Interfaces ---

// Optional logger hook for threat-intel middleware
export type ThreatIntelLogger = (
  level: 'info' | 'warn' | 'error',
  message: string,
  meta?: Record<string, any>
) => void;

export interface ThreatScore {
  score: number; // 0 (safe) to 100 (dangerous)
  tags: string[]; // e.g., 'tor', 'botnet', 'spam'
  source: string; // Provider name
  geo?: GeoLocation; // GeoIP Data
  metadata?: Record<string, any>;
}

export interface GeoLocation {
  country: string;
  city?: string;
  asn?: number;
  isp?: string;
  isDatacenter?: boolean;
  isTor?: boolean;
  isProxy?: boolean;
}

/**
 * Interface for any external Threat Intelligence Source.
 */
export interface ThreatProvider {
  name: string;
  check(ip: string): Promise<ThreatScore | null>;
}

export interface ThreatIntelOptions {
  blockThreshold?: number; // Default: 80
  providers?: ThreatProvider[];
  ipBlocklistUrls?: string[];
  refreshIntervalMs?: number;
  cacheTtlSeconds?: number;
  redisClient?: any;

  /**
   * Enable GeoIP lookups (Mock/Local if no real DB provided)
   */
  enableGeoIP?: boolean;

  /**
   * AbuseIPDB API Key for real-time checks
   */
  abuseIpDbKey?: string;
}

// --- Built-in Providers ---

class AbuseIPDBProvider implements ThreatProvider {
  name = 'AbuseIPDB';
  constructor(private apiKey: string) {}

  async check(ip: string): Promise<ThreatScore | null> {
    // In a real scenario, this fetches https://api.abuseipdb.com/api/v2/check
    // We mock the interface logic but return null unless implemented by user to avoid rate limits/errors
    // without valid keys.
    if (!this.apiKey || !ip) return null;
    return null; // Implement fetch logic here for production
  }
}

class StaticBlocklistProvider implements ThreatProvider {
  name = 'StaticBlocklist';
  private blocklist: Set<string> = new Set();

  constructor(private urls: string[] = []) {
    if (urls.length > 0) this.refresh().catch(console.error);
  }

  async refresh() {
    // Fetch logic reused from original
    for (const url of this.urls) {
      try {
        const data = await this.fetchList(url);
        data.split(/\r?\n/).forEach((line) => {
          if (line && !line.startsWith('#')) this.blocklist.add(line.trim());
        });
      } catch (e) {
        /* ignore */
      }
    }
  }

  private fetchList(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const client = url.startsWith('https') ? https : http;
      client
        .get(url, (res) => {
          let data = '';
          res.on('data', (c) => (data += c));
          res.on('end', () => resolve(data));
        })
        .on('error', reject);
    });
  }

  async check(ip: string): Promise<ThreatScore | null> {
    if (this.blocklist.has(ip)) {
      return { score: 100, tags: ['static_blocklist'], source: this.name };
    }
    return null;
  }
}

// --- Core Logic ---

export class ThreatIntelEngine {
  private cache: Map<string, { score: ThreatScore; expires: number }> =
    new Map();
  private providers: ThreatProvider[] = [];

  constructor(private options: ThreatIntelOptions) {
    if (options.providers) this.providers.push(...options.providers);

    // Auto-add static blocklists
    if (options.ipBlocklistUrls?.length) {
      this.providers.push(new StaticBlocklistProvider(options.ipBlocklistUrls));
    }

    // Auto-add AbuseIPDB if key present
    if (options.abuseIpDbKey) {
      this.providers.push(new AbuseIPDBProvider(options.abuseIpDbKey));
    }
  }

  private async getGeoIP(ip: string): Promise<GeoLocation | undefined> {
    if (!this.options.enableGeoIP) return undefined;

    // Mock GeoIP for dev environment or hook into MaxMind here
    // Real implementation would require 'geoip-lite' or 'maxmind' package
    const isLocal =
      ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.');

    return {
      country: isLocal ? 'LO' : 'US', // Default to Local/US
      city: isLocal ? 'Localhost' : 'Unknown',
      isDatacenter: false,
      isTor: false,
    };
  }

  public async evaluate(ip: string): Promise<ThreatScore> {
    // 1. Cache Check
    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) return cached.score;

    // 2. Parallel Provider Lookup
    let maxScore = 0;
    const combinedTags: string[] = [];
    let source = 'none';

    const results = await Promise.allSettled(
      this.providers.map((p) => p.check(ip))
    );

    for (const res of results) {
      if (res.status === 'fulfilled' && res.value) {
        if (res.value.score > maxScore) {
          maxScore = res.value.score;
          source = res.value.source;
        }
        if (res.value.tags) combinedTags.push(...res.value.tags);
      }
    }

    // 3. GeoIP Analysis
    const geo = await this.getGeoIP(ip);
    if (geo && geo.isTor) {
      maxScore = Math.max(maxScore, 90);
      combinedTags.push('tor_exit_node');
    }

    const result: ThreatScore = {
      score: maxScore,
      tags: [...new Set(combinedTags)],
      source,
      geo,
    };

    // 4. Cache Result (1 hour default)
    this.cache.set(ip, {
      score: result,
      expires: Date.now() + (this.options.cacheTtlSeconds || 3600) * 1000,
    });

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

      // Skip invalid or local IPs
      if (ip === '127.0.0.1' || ip === '::1') return next();

      const threat = await engine.evaluate(ip);

      if (threat.score >= THRESHOLD) {
        logger.warn(
          `Threat Intel Block: IP ${ip} scored ${threat.score} (${threat.source})`,
          {
            tags: threat.tags,
            geo: threat.geo,
          }
        );

        return res.status(403).json({
          status: 'error',
          code: 'SECURITY_THREAT_DETECTED',
          message: 'Access denied due to poor reputation.',
          request_id: Date.now(),
        });
      }

      // Attach Threat Info to Request for downstream use (e.g. Rate Limiter adjustments)
      (req as any).threatScore = threat;

      next();
    } catch (error) {
      logger.error('Error in Threat Intel middleware', error);
      next();
    }
  };
}
