import { Request, Response, NextFunction } from 'express';
import { faker } from '@faker-js/faker';

export interface HoneywallLogger {
  warn(message: string, meta?: any): void;
  info(message: string, meta?: any): void;
  error(message: string, meta?: any): void;
}

export interface HoneywallOptions {
  /**
   * List of exact paths to act as honeypots.
   * e.g., ['/admin', '/wp-login.php', '/.env']
   */
  honeypotPaths?: string[];

  /**
   * List of RegExp patterns to match honeypot paths.
   */
  honeypotPatterns?: RegExp[];

  /**
   * Sensitivity of the "Auto-Discovery" (detecting scans).
   * 'low': strict path matching only.
   * 'medium': checks for common scanners/user-agents.
   * 'high': suspicious headers/payloads.
   * Default: 'medium'
   */
  sensitivity?: 'low' | 'medium' | 'high';

  /**
   * Response strategy for trapped requests.
   * 'hang': Keep connection open indefinitely (Tarpit).
   * 'fake-data': Return realistic fake credentials/data.
   * 'error': Return 403/404.
   * Default: 'fake-data'
   */
  strategy?: 'hang' | 'fake-data' | 'error';

  /**
   * Delay in milliseconds before responding (to waste attacker time).
   * Default: 0 (no delay)
   */
  tarpitDelay?: number;

  /**
   * If true, sets a "Canary" cookie (e.g., "admin_session").
   * If this cookie is seen in future requests from ANY IP, it triggers an alert.
   */
  canaryCookie?: boolean;

  /**
   * Callback to execute when a honeypot is tripped (e.g., ban IP).
   */
  onTrip?: (req: Request, sourceIp: string) => void;

  logger?: HoneywallLogger;
}

const defaultLogger: HoneywallLogger = {
  warn: (msg, meta) => console.warn(`[HONEYWALL:WARN] ${msg}`, meta || ''),
  info: (msg) => console.log(`[HONEYWALL:INFO] ${msg}`),
  error: (msg, meta) => console.error(`[HONEYWALL:ERROR] ${msg}`, meta || '')
};

/**
 * Enterprise Honeywall Middleware (Deception & Defense)
 * 
 * 1. Lures attackers into accessing fake sensitive endpoints.
 * 2. Wastes attacker time with Tarpit delays.
 * 3. Identifies scanners via Canary Tokens.
 * 4. Provides realistic fake data to confuse active recon.
 */
export function createHoneypotMiddleware(options: HoneywallOptions = {}) {
  const logger = options.logger || defaultLogger;
  const paths = new Set(options.honeypotPaths || [
    '/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config.json',
    '/backup.sql', '/.git/config', '/api/keys', '/id_rsa'
  ]);
  const patterns = options.honeypotPatterns || [];
  const strategy = options.strategy || 'fake-data';
  const tarpitDelay = options.tarpitDelay || 0;
  const sensitivity = options.sensitivity || 'medium';

  // Suspicious Agents (for medium/high sensitivity)
  const suspiciousAgents = [
    'sqlmap', 'nikto', 'nessus', 'metasploit', 'nmap', 'burpsuite', 
    'wpscan', 'acunetix', 'zaproxy', 'havij'
  ];

  const checkHoneypot = (req: Request): boolean => {
    // 1. Exact Path Match
    if (paths.has(req.path) || paths.has(req.url)) return true;

    // 2. Regex Match
    if (patterns.some(p => p.test(req.url))) return true;

    // 3. User-Agent Scan (Medium+)
    if (sensitivity !== 'low') {
        const ua = (req.headers['user-agent'] || '').toLowerCase();
        if (suspiciousAgents.some(agent => ua.includes(agent))) return true;
    }

    return false;
  };

  const generateFakeResponse = () => {
    // Generate realistic looking dump
    return {
      status: 'success',
      apiVersion: '3.4.1',
      environment: 'production',
      keys: Array.from({ length: 3 }, () => ({
        id: faker.string.uuid(),
        secret: `sk_live_${faker.string.alphanumeric(48)}`, // Stripe-like
        role: 'full_access',
        lastUsed: faker.date.recent().toISOString()
      })),
      database: {
        host: 'db-prod-primary.internal',
        port: 5432,
        user: 'postgres',
        password_hash: faker.string.alphanumeric(64) // Not a real password
      }
    };
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    // Check if trap triggered
    if (!checkHoneypot(req)) {
      // Passive check: Did they provide a canary cookie?
      if (options.canaryCookie && req.cookies && req.cookies['__admin_session_v2']) {
         logger.warn(`Canary Token Tripped! IP ${req.ip} is reusing a decoy cookie.`);
         // We treat this as a trip too
         if (options.onTrip) options.onTrip(req, req.ip || 'unknown');
         return res.status(403).send('Session Invalidated'); 
      }
      return next();
    }

    // --- TRAP TRIGGERED ---
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    logger.warn(`Honeywall Trap Triggered: IP ${ip} accessed ${req.path}`);

    // Execute Callback (e.g. IP Ban)
    if (options.onTrip) {
      options.onTrip(req, ip as string);
    }

    // 1. Tarpit Strategy (Hang)
    if (strategy === 'hang') {
        // Just never reply? Or reply extremely slowly?
        // Node might timeout, so let's just write slowly or wait long.
        if (tarpitDelay > 0) {
            await new Promise(resolve => setTimeout(resolve, tarpitDelay));
        } else {
             // Infinite-ish wait (until socket timeout)
             // We won't resolve response.
             return; 
        }
    }

    // 2. Delay (even for other strategies)
    if (tarpitDelay > 0 && strategy !== 'hang') {
        await new Promise(resolve => setTimeout(resolve, tarpitDelay));
    }

    // 3. Canary Insertion
    if (options.canaryCookie) {
        res.cookie('__admin_session_v2', faker.string.alphanumeric(32), {
            httpOnly: true,
            secure: true,
            maxAge: 31536000000 // 1 year
        });
    }

    // 4. Response
    if (strategy === 'error') {
        return res.status(404).send('Not Found'); // Pretend it doesn't exist
    }

    if (strategy === 'fake-data') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('X-Server-Id', 'prod-worker-01'); // Fake header
        return res.status(200).json(generateFakeResponse());
    }

    next();
  };
}