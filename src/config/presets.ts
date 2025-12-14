// src/config/presets.ts
import { SecurityConfig } from '../types';

export const presets = {
  /**
   * Basic security for simple apps
   */
  basic: {
    helmet: true,
    cors: true,
    rateLimit: { windowMs: 900000, max: 100 },
    csrf: true,
    xss: true,
    sqlInjection: true,
    logging: { level: 'error' }
  } as Partial<SecurityConfig>,

  /**
   * API security for REST/GraphQL APIs
   */
  api: {
    helmet: true,
    cors: { origin: true, credentials: true },
    rateLimit: { windowMs: 60000, max: 1000 },
    xss: { level: 'strict' },
    sqlInjection: { level: 'strict' },
    requestValidation: true,
    securityHeaders: true,
    logging: { level: 'info', audit: true }
  } as Partial<SecurityConfig>,

  /**
   * Enterprise security with all features
   */
  enterprise: {
    helmet: { advanced: true },
    cors: { origin: true, credentials: true, preflightContinue: false },
    rateLimit: { windowMs: 60000, max: 500, keyGenerator: 'advanced' },
    csrf: { cookie: true },
    xss: { level: 'paranoid' },
    sqlInjection: { level: 'paranoid' },
    requestValidation: { strict: true },
    securityHeaders: { advanced: true },
    honeypot: { enabled: true, level: 'aggressive' },
    threatIntel: { enabled: true, providers: ['abuseipdb', 'virustotal'] },
    anomalyDetection: { enabled: true, ml: true },
    logging: { level: 'detailed', audit: true, siem: true },
    strictMode: true
  } as Partial<SecurityConfig>,

  /**
   * Honeypot-focused configuration
   */
  honeypot: {
    helmet: true,
    cors: true,
    rateLimit: { windowMs: 60000, max: 5000 }, // Allow more for tracking
    honeypot: {
      enabled: true,
      level: 'aggressive',
      endpoints: ['/admin', '/wp-login', '/phpmyadmin', '/.env'],
      deception: 'advanced'
    },
    threatIntel: { enabled: true, realtime: true },
    logging: { level: 'detailed', audit: true },
    strictMode: false // Don't block, just monitor
  } as Partial<SecurityConfig>,

  /**
   * E-commerce security
   */
  ecommerce: {
    helmet: { contentSecurityPolicy: { directives: { 'script-src': ["'self'", "'unsafe-inline'"] } } },
    cors: { origin: true, credentials: true },
    rateLimit: { windowMs: 60000, max: 200 },
    csrf: { cookie: true, httpOnly: true },
    xss: { level: 'strict' },
    sqlInjection: { level: 'strict' },
    requestValidation: { strict: true },
    securityHeaders: true,
    logging: { level: 'info', audit: true }
  } as Partial<SecurityConfig>,

  /**
   * Development configuration
   */
  development: {
    helmet: true,
    cors: { origin: '*' },
    rateLimit: false,
    csrf: false,
    xss: true,
    sqlInjection: true,
    logging: { level: 'debug' },
    strictMode: false
  } as Partial<SecurityConfig>
};