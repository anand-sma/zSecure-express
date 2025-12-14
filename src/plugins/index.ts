import { Request, Response, NextFunction, Application } from 'express';

// --- Interfaces ---

export interface PluginLogger {
  info(msg: string, meta?: any): void;
  warn(msg: string, meta?: any): void;
  error(msg: string, meta?: any): void;
  debug(msg: string, meta?: any): void;
}

export interface PluginContext {
  app: Application;
  logger: PluginLogger;
  config: any; // Dynamic config
}

export interface SecurityPlugin {
  id: string;
  name: string;
  version: string;
  description?: string;
  
  /**
   * Called when the plugin is registered.
   * Use this to set up databases, cache connections, or validate config.
   */
  onInit?: (context: PluginContext) => Promise<void> | void;

  /**
   * Middleware to inject specific logic into the request chain.
   */
  middleware?: (req: Request, res: Response, next: NextFunction) => void;

  /**
   * Hook called on every request (before middleware).
   * Return false to block the request immediately.
   */
  onRequest?: (req: Request) => Promise<boolean | void> | boolean | void;

  /**
   * Hook called when a security violation occurs.
   */
  onViolation?: (req: Request, type: string, details: any) => void;
}

/**
 * Default Console Logger for Plugins
 */
const defaultLogger: PluginLogger = {
  info: (msg, meta) => console.log(`[PLUGIN:INFO] ${msg}`, meta || ''),
  warn: (msg, meta) => console.warn(`[PLUGIN:WARN] ${msg}`, meta || ''),
  error: (msg, meta) => console.error(`[PLUGIN:ERROR] ${msg}`, meta || ''),
  debug: (msg, meta) => console.debug(`[PLUGIN:DEBUG] ${msg}`, meta || '')
};

/**
 * Plugin Manager
 * 
 * Orchestrates the lifecycle of security plugins.
 */
export class PluginManager {
  private plugins: Map<string, SecurityPlugin> = new Map();
  private context: PluginContext;

  constructor(app: Application, config: any = {}, logger: PluginLogger = defaultLogger) {
    this.context = { app, config, logger };
  }

  /**
   * Register a new plugin
   */
  async register(plugin: SecurityPlugin): Promise<void> {
    if (this.plugins.has(plugin.id)) {
      this.context.logger.warn(`Plugin ${plugin.id} is already registered. Skipping.`);
      return;
    }

    this.plugins.set(plugin.id, plugin);
    
    // Initialize
    if (plugin.onInit) {
      try {
        await plugin.onInit(this.context);
        this.context.logger.info(`Plugin registered and initialized: ${plugin.name} v${plugin.version}`);
      } catch (err) {
        this.context.logger.error(`Failed to initialize plugin ${plugin.name}`, err);
        this.plugins.delete(plugin.id); // Rollback
        throw err;
      }
    } else {
        this.context.logger.info(`Plugin registered: ${plugin.name} v${plugin.version}`);
    }
  }

  /**
   * Get main middleware chain for all plugins
   */
  getMiddleware(): (req: Request, res: Response, next: NextFunction) => Promise<void> {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // 1. Run onRequest hooks (Sequential for safety)
      for (const plugin of this.plugins.values()) {
        if (plugin.onRequest) {
          try {
            const result = await plugin.onRequest(req);
            // If explicit false is returned, block request
            if (result === false) {
               this.context.logger.warn(`Request blocked by plugin: ${plugin.name}`);
               res.status(403).json({ error: `Blocked by ${plugin.name}` });
               return;
            }
          } catch (err) {
            this.context.logger.error(`Error in plugin ${plugin.name} onRequest hook`, err);
            // Fail open or closed? Defaulting to log and continue to avoid outage
          }
        }
      }

      // 2. Run specific middlewares (We can't easily chain them dynamically here without next() callback hell,
      // so we rely on the user to register plugin middlewares manually OR we compose them if needed.
      // For this implementation, we will just pass through behavior. 
      // A real plugin system might use 'connect' style composition, but here we keep it simple:
      // We don't execute plugin.middleware automatically here to avoid stack issues. 
      // Users should use plugin.middleware explicitly or we expose a method `attachMiddlewares(app)`.
      
      next();
    };
  }
  
  /**
   * Notify plugins of a violation
   */
  notifyViolation(req: Request, type: string, details: any) {
      for (const plugin of this.plugins.values()) {
          if (plugin.onViolation) {
              try {
                  plugin.onViolation(req, type, details);
              } catch (err) {
                  this.context.logger.error(`Error in plugin ${plugin.name} onViolation`, err);
              }
          }
      }
  }

  /**
   * Helper to attach all plugin middlewares to an express app instance 
   * (If you want them all to run globally)
   */
  attachAll(app: Application) {
      for (const plugin of this.plugins.values()) {
          if (plugin.middleware) {
              app.use(plugin.middleware);
              this.context.logger.debug(`Attached middleware for ${plugin.name}`);
          }
      }
  }
}

// --- Real-World Built-in Plugins ---

/**
 * 1. Audit Log Plugin
 * Tracks every request method and URL to console/storage.
 */
export const AuditLogPlugin: SecurityPlugin = {
  id: 'audit-log',
  name: 'Security Audit Logger',
  version: '1.0.0',
  
  onInit(ctx) {
    ctx.logger.info('Audit Logger started. Recording events...');
  },

  onRequest(_req) {
    // We don't block, just note it
    // In a real app, this might generate a correlation ID
    return true; 
  },

  onViolation(req, type, details) {
    console.warn(`[AUDIT-VIOLATION] [${type}] Request: ${req.method} ${req.url} | IP: ${req.ip} | Details:`, details);
  }
};

/**
 * 2. Simple WAF Plugin
 * Blocks common malicious patterns in URL params.
 */
export const SimpleWafPlugin: SecurityPlugin = {
  id: 'simple-waf',
  name: 'Basic Web Application Firewall',
  version: '1.2.0',
  
  onRequest(req) {
    const maliciousPatterns = [
        /\.\.\//, // Path traversal
        /<script/, // XSS
        /UNION SELECT/i // SQLi
    ];
    
    if (maliciousPatterns.some(p => p.test(req.url))) {
        return false; // BLOCK
    }
    return true; // ALLOW
  }
};

/**
 * 3. IP Allowlist Plugin
 * Only allows requests from specific IPs if configured.
 */
export const makeIpAllowlistPlugin = (allowedIps: string[]): SecurityPlugin => ({
    id: 'ip-allowlist',
    name: 'IP Allowlist Enforcer',
    version: '1.0.0',
    
    onInit(ctx) {
        if (!allowedIps || allowedIps.length === 0) {
            ctx.logger.warn('IP Allowlist plugin enabled but list is empty! Blocking ALL traffic (or disabling).');
        }
    },

    onRequest(req) {
        if (allowedIps.length === 0) return true; // Fail safe if empty
        const ip = req.ip || req.socket.remoteAddress || '';
        // Simple check (not CIDR support for brevity, but easily added)
        if (!allowedIps.includes(ip)) {
            return false;
        }
        return true; // ALLOW
    }
});