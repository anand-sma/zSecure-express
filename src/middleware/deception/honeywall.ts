import { Request, Response, NextFunction } from 'express';
import { faker } from '@faker-js/faker';
import { logger } from '../../utils/logger';

// --- Interfaces ---

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
   * 'fake-login': Return a fake HTML login page.
   * 'error': Return 403/404.
   * Default: 'fake-data'
   */
  strategy?: 'hang' | 'fake-data' | 'fake-login' | 'error';

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
}

/**
 * Enterprise Honeywall Middleware (Deception & Defense)
 * 
 * 1. Lures attackers into accessing fake sensitive endpoints.
 * 2. Wastes attacker time with Tarpit delays.
 * 3. Identifies scanners via Canary Tokens.
 * 4. Provides realistic fake data/login pages to confuse active recon.
 */
export function createHoneypotMiddleware(options: HoneywallOptions = {}) {
  const paths = new Set(options.honeypotPaths || [
    '/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config.json',
    '/backup.sql', '/.git/config', '/api/keys', '/id_rsa', '/aws/credentials'
  ]);
  const patterns = options.honeypotPatterns || [];
  const strategy = options.strategy || 'fake-data';
  const tarpitDelay = options.tarpitDelay || 0;
  const sensitivity = options.sensitivity || 'medium';

  // Suspicious Agents (for medium/high sensitivity)
  const suspiciousAgents = [
    'sqlmap', 'nikto', 'nessus', 'metasploit', 'nmap', 'burpsuite', 
    'wpscan', 'acunetix', 'zaproxy', 'havij', 'masscan'
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

  const generateFakeData = () => {
    return {
      status: 'success',
      apiVersion: 'v4.1.0-alpha',
      environment: 'production-eu-west',
      maintenance_mode: false,
      debug: true, // Lure
      keys: Array.from({ length: 2 }, () => ({
        key_id: faker.string.uuid(),
        secret: `sk_prod_${faker.string.alphanumeric(48)}`,
        acls: ['admin', 'write:all'],
        created: faker.date.past().toISOString()
      })),
      database: {
        host: '10.0.12.54', // Fake internal IP
        port: 5432,
        user: 'admin_readonly',
        pass: faker.string.alphanumeric(16)
      }
    };
  };

  const generateFakeLogin = () => {
      // Simple deceptive login page
      return `
      <!DOCTYPE html>
      <html>
      <head>
          <title>Admin Portal - Unauthorized Access Logged</title>
          <style>
            body { font-family: -apple-system, system-ui, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 320px; }
            h2 { margin-top: 0; color: #1a202c; }
            input { width: 100%; padding: 0.5rem; margin: 0.5rem 0; border: 1px solid #e2e8f0; border-radius: 4px; }
            button { width: 100%; padding: 0.5rem; background: #3182ce; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
            button:hover { background: #2c5282; }
          </style>
      </head>
      <body>
          <div class="card">
              <h2>System Login</h2>
              <p style="color:red; font-size: 0.9em;">Secure Environment. All actions monitored.</p>
              <form method="POST" action="/login/authenticate">
                  <div>
                      <label>Username (SSO ID)</label>
                      <input type="text" name="username" required>
                  </div>
                  <div>
                      <label>Password</label>
                      <input type="password" name="password" required>
                  </div>
                  <button type="submit">Sign In</button>
              </form>
          </div>
      </body>
      </html>
      `;
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    // Check if trap triggered
    if (!checkHoneypot(req)) {
      // Passive check: Did they provide a canary cookie?
      if (options.canaryCookie && req.cookies && req.cookies['__admin_session_v2']) {
         logger.warn(`Canary Token Tripped! IP ${req.ip} is reusing a decoy cookie.`);
         if (options.onTrip) options.onTrip(req, req.ip || 'unknown');
         return res.status(403).send('Session Invalidated'); 
      }
      return next();
    }

    // --- TRAP TRIGGERED ---
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    logger.warn(`Honeywall Trap Triggered: IP ${ip} accessed ${req.path}`, {
        method: req.method,
        uas: req.headers['user-agent']
    });

    // Execute Callback (e.g. IP Ban)
    // We do this async to not block response if heavy
    if (options.onTrip) {
      setTimeout(() => options.onTrip!(req, ip as string), 0);
    }

    // 1. Tarpit Strategy (Hang/Delay)
    // Delay always applied if set, except for pure 'hang' which implies max delay
    if (tarpitDelay > 0) {
        await new Promise(resolve => setTimeout(resolve, tarpitDelay));
    }

    if (strategy === 'hang') {
         // Keep open until client timeout or socket destruction
         // Just return undefined to hang express? No, that leaks memory.
         // Better to just not call next() and not send res, but eventually node timeouts.
         // A very long delay is safer.
         // Actually, let's just close the connection abruptly to confuse them.
         return req.socket.destroy();
    }

    // 2. Canary Insertion
    if (options.canaryCookie) {
        res.cookie('__admin_session_v2', faker.string.alphanumeric(32), {
            httpOnly: true,
            secure: true,
            maxAge: 31536000000 // 1 year
        });
    }

    // 3. Response Generation
    // Fake headers to look like internal system
    res.setHeader('X-Powered-By', 'Internal-System-v2');
    res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');

    if (strategy === 'error') {
        return res.status(404).send('Not Found'); 
    }

    if (strategy === 'fake-login') {
         // If GET, show form. If POST, accept and redirect?
         if (req.method === 'GET') {
             res.status(200).send(generateFakeLogin());
         } else {
             // Fake success then redirect to same page or 403
             res.status(200).send('<h1>MFA Token Required</h1><p>Please check your hardware token.</p>');
         }
         return;
    }

    if (strategy === 'fake-data') {
        res.setHeader('Content-Type', 'application/json');
        return res.status(200).json(generateFakeData());
    }

    next();
  };
}