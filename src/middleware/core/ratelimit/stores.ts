/**
 * Rate Limit Storage Interface & Adapters
 */

export interface RateLimitRecord {
  hits: number;
  resetTime: number;
  activeRequests?: number; // For concurrency limiting
  abuseScore?: number;
}

export interface RateLimitStore {
  /**
   * Increment hit count for a key. Returns updated record.
   */
  increment(key: string, windowMs: number): Promise<RateLimitRecord>;

  /**
   * Decrement hit count (mostly used for concurrency limiting).
   */
  decrement(key: string): Promise<void>;

  /**
   * Get current record without modifying.
   */
  get(key: string): Promise<RateLimitRecord | undefined>;

  /**
   * Reset a key immediately.
   */
  reset(key: string): Promise<void>;
  
  /**
   * Ban a key for a duration.
   */
  block(key: string, durationMs: number): Promise<void>;
}

/**
 * In-Memory Store Implementation (Default)
 */
export class MemoryStore implements RateLimitStore {
  private hits = new Map<string, RateLimitRecord>();
  private blocks = new Map<string, number>(); // key -> expiry time
  private cleanupInterval: NodeJS.Timeout;

  constructor(cleanupIntervalMs: number = 60000) {
    this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
    if (this.cleanupInterval.unref) this.cleanupInterval.unref();
  }

  async increment(key: string, windowMs: number): Promise<RateLimitRecord> {
    const now = Date.now();
    
    // Check block
    const blockExpiry = this.blocks.get(key);
    if (blockExpiry && blockExpiry > now) {
        throw new Error('BLOCKED');
    }

    let record = this.hits.get(key);
    
    if (!record || now > record.resetTime) {
      record = { hits: 0, resetTime: now + windowMs, activeRequests: 0 };
    }
    
    record.hits++;
    if (record.activeRequests !== undefined) record.activeRequests++;
    
    this.hits.set(key, record);
    return record;
  }

  async decrement(key: string): Promise<void> {
    const record = this.hits.get(key);
    if (record && record.activeRequests && record.activeRequests > 0) {
      record.activeRequests--;
    }
  }

  async get(key: string): Promise<RateLimitRecord | undefined> {
    return this.hits.get(key);
  }

  async reset(key: string): Promise<void> {
    this.hits.delete(key);
    this.blocks.delete(key);
  }

  async block(key: string, durationMs: number): Promise<void> {
    this.blocks.set(key, Date.now() + durationMs);
  }

  private cleanup() {
    const now = Date.now();
    for (const [key, record] of this.hits.entries()) {
      if (now > record.resetTime && (!record.activeRequests || record.activeRequests === 0)) {
        this.hits.delete(key);
      }
    }
    for (const [key, expiry] of this.blocks.entries()) {
      if (now > expiry) this.blocks.delete(key);
    }
  }
}

/**
 * Redis Store Implementation
 * Support for distributed counters and bans.
 */
export class RedisStore implements RateLimitStore {
  constructor(private client: any, private prefix: string = 'rl:') {}

  async increment(key: string, windowMs: number): Promise<RateLimitRecord> {
    const k = `${this.prefix}${key}`;
    const blocked = await this.client.get(`${k}:blocked`);
    
    if (blocked) {
       throw new Error('BLOCKED');
    }

    // Simplest Redis approach:
    // SET NX PX ... to init
    // INCR
    // PTTL
    
    const now = Date.now();
    const hits = await this.client.incr(k);
    if (hits === 1) {
      await this.client.pexpire(k, windowMs);
    }
    const ttl = await this.client.pttl(k);
    
    return {
      hits,
      resetTime: now + (ttl > 0 ? ttl : windowMs),
      activeRequests: 0 // Redis simple store doesn't track active easily without extra complexity
    };
  }
  
  async decrement(_key: string): Promise<void> {
     // Not implemented for simple Redis windowing yet. 
  }

  async get(key: string): Promise<RateLimitRecord | undefined> {
    const k = `${this.prefix}${key}`;
    const hits = await this.client.get(k);
    const ttl = await this.client.pttl(k);
    return hits ? { hits: parseInt(hits), resetTime: Date.now() + ttl } : undefined;
  }

  async reset(key: string): Promise<void> {
    await this.client.del(`${this.prefix}${key}`);
    await this.client.del(`${this.prefix}${key}:blocked`);
  }

  async block(key: string, durationMs: number): Promise<void> {
    await this.client.set(`${this.prefix}${key}:blocked`, '1', 'PX', durationMs);
  }
}
