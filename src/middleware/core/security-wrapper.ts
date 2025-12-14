/**
 * Security Wrapper - Main orchestrator for all security middlewares
 */
import { Request, Response, NextFunction } from 'express';
import { SecurityConfig, MiddlewareChain } from '../../types/core';
import { presets } from '../../config/presets';
import { logger } from '../../utils/logger';

import { createCorsMiddleware } from './cors-protection';
import { createHelmetMiddleware } from './helmet-enhanced';
import { createSecurityHeadersMiddleware } from './security-headers';
import { createRateLimitMiddleware } from './rate-limiting';
import { createRequestValidationMiddleware } from './request-validation';
import { createCsrfMiddleware } from './csrf-protection';
import { createXSSMiddleware } from '../advanced/xss-protection';
import { createSQLInjectionMiddleware } from '../advanced/sql-injection';
import { createThreatIntelMiddleware } from '../advanced/threat-intel';
import { createAnomalyDetectionMiddleware } from '../advanced/anomaly-detection';
import { createHoneypotMiddleware } from '../deception/honeywall';

/**
 * Extracts options from config value.
 * - If boolean `true`, returns undefined (use defaults)
 * - If object, returns the object
 * - If false/undefined, should not call middleware
 */
function extractOptions<T>(value: boolean | T | undefined): T | undefined {
  if (value === true) return undefined;
  if (value && typeof value === 'object') return value as T;
  return undefined;
}

export class SecurityWrapper {
  private config: SecurityConfig;
  private middlewares: MiddlewareChain[] = [];

  constructor(options: Partial<SecurityConfig> = {}) {
    this.config = this.mergeConfig(options);
    this.initializeMiddlewares();
  }

  /**
   * Main middleware function - applies all security layers
   */
  public handler(): (req: Request, res: Response, next: NextFunction) => void {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        for (const middleware of this.middlewares) {
          await this.applyMiddleware(middleware, req, res);
        }
        next();
      } catch (error) {
        this.handleSecurityError(error, req, res);
      }
    };
  }

  /**
   * Static method for preset configurations
   */
  public static preset(name: keyof typeof presets): SecurityWrapper {
    return new SecurityWrapper(presets[name]);
  }

  /**
   * Chainable API for custom configurations
   */
  public withHelmet(options?: Record<string, unknown>): this {
    this.config.helmet = options || true;
    this.initializeMiddlewares();
    return this;
  }

  public withRateLimit(options?: Record<string, unknown>): this {
    this.config.rateLimit = options || true;
    this.initializeMiddlewares();
    return this;
  }

  public withHoneypot(options?: Record<string, unknown>): this {
    this.config.honeypot = options || true;
    this.initializeMiddlewares();
    return this;
  }

  private initializeMiddlewares(): void {
    this.middlewares = [];

    // Order matters! Apply in security-best-practice order
    if (this.config.logging?.audit) this.addAuditLogging();
    if (this.config.cors) this.addCors();
    if (this.config.helmet) this.addHelmet();
    if (this.config.securityHeaders) this.addSecurityHeaders();
    if (this.config.rateLimit) this.addRateLimit();
    if (this.config.requestValidation) this.addRequestValidation();
    if (this.config.xss) this.addXSSProtection();
    if (this.config.sqlInjection) this.addSQLInjection();
    if (this.config.csrf) this.addCSRF();
    if (this.config.honeypot) this.addHoneypot();
    if (this.config.threatIntel) this.addThreatIntel();
    if (this.config.anomalyDetection) this.addAnomalyDetection();
  }

  private addCors(): void {
    this.middlewares.push({
      name: 'cors',
      handler: createCorsMiddleware(extractOptions(this.config.cors)),
      priority: 1
    });
  }

  private addHelmet(): void {
    this.middlewares.push({
      name: 'helmet',
      handler: createHelmetMiddleware(extractOptions(this.config.helmet)),
      priority: 2
    });
  }

  private addSecurityHeaders(): void {
    this.middlewares.push({
      name: 'securityHeaders',
      handler: createSecurityHeadersMiddleware(extractOptions(this.config.securityHeaders)),
      priority: 3
    });
  }

  private addRateLimit(): void {
    this.middlewares.push({
      name: 'rateLimit',
      handler: createRateLimitMiddleware(extractOptions(this.config.rateLimit)),
      priority: 4
    });
  }

  private addRequestValidation(): void {
    this.middlewares.push({
      name: 'requestValidation',
      handler: createRequestValidationMiddleware(extractOptions(this.config.requestValidation)),
      priority: 5
    });
  }

  private addXSSProtection(): void {
    this.middlewares.push({
      name: 'xss',
      handler: createXSSMiddleware(extractOptions(this.config.xss)),
      priority: 6
    });
  }

  private addSQLInjection(): void {
    this.middlewares.push({
      name: 'sqlInjection',
      handler: createSQLInjectionMiddleware(extractOptions(this.config.sqlInjection)),
      priority: 7
    });
  }

  private addCSRF(): void {
    this.middlewares.push({
      name: 'csrf',
      handler: createCsrfMiddleware(extractOptions(this.config.csrf)),
      priority: 8
    });
  }

  private addHoneypot(): void {
    this.middlewares.push({
      name: 'honeypot',
      handler: createHoneypotMiddleware(extractOptions(this.config.honeypot)),
      priority: 50
    });
  }

  private addThreatIntel(): void {
    this.middlewares.push({
      name: 'threatIntel',
      handler: createThreatIntelMiddleware(extractOptions(this.config.threatIntel)),
      priority: 60
    });
  }

  private addAnomalyDetection(): void {
    this.middlewares.push({
      name: 'anomalyDetection',
      handler: createAnomalyDetectionMiddleware(extractOptions(this.config.anomalyDetection)),
      priority: 70
    });
  }

  private addAuditLogging(): void {
    this.middlewares.push({
      name: 'auditLogging',
      handler: (req: Request, _res: Response, next: NextFunction) => {
        logger.info(`[Audit] ${req.method} ${req.url} - IP: ${req.ip}`);
        next();
      },
      priority: 0
    });
  }

  private async applyMiddleware(
    middleware: MiddlewareChain,
    req: Request,
    res: Response
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const next = (err?: unknown) => {
        if (err) reject(err);
        else resolve();
      };
      
      try {
        const result = middleware.handler(req, res, next);
        // Handle async middlewares
        if (result instanceof Promise) {
          result.catch(reject);
        }
      } catch (err) {
        reject(err);
      }
    });
  }

  private handleSecurityError(
    error: unknown,
    req: Request,
    res: Response
  ): void {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logger.error('Security middleware error:', errorMessage);
    
    // Don't expose internal errors in production
    const message = process.env.NODE_ENV === 'production'
      ? 'Security check failed'
      : errorMessage;
    
    res.status(403).json({
      error: 'Security Violation',
      message,
      requestId: req.id,
      timestamp: new Date().toISOString()
    });
  }

  private mergeConfig(options: Partial<SecurityConfig>): SecurityConfig {
    const defaults: SecurityConfig = {
      helmet: true,
      cors: true,
      rateLimit: true,
      csrf: true,
      xss: true,
      sqlInjection: true,
      requestValidation: true,
      securityHeaders: true,
      honeypot: false,
      threatIntel: false,
      anomalyDetection: false,
      logging: {
        level: 'warn',
        audit: false
      },
      strictMode: false
    };

    return { ...defaults, ...options };
  }
}

/**
 * Quick setup function for express.use()
 */
export function secure(options?: Partial<SecurityConfig>) {
  const wrapper = new SecurityWrapper(options);
  return wrapper.handler();
}