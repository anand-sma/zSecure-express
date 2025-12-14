/**
 * Internal Core Types - No external dependencies
 * 
 * These types are used internally and do not depend on middleware modules.
 * This prevents circular dependencies.
 */

import { Request, Response, NextFunction } from 'express';

// ============================================================================
// Base Logger Interface (shared across all middlewares)
// ============================================================================
export interface BaseLogger {
  info(message: string, ...meta: unknown[]): void;
  warn(message: string, ...meta: unknown[]): void;
  error(message: string, ...meta: unknown[]): void;
  debug?(message: string, ...meta: unknown[]): void;
}

// ============================================================================
// Middleware Chain
// ============================================================================
export interface MiddlewareChain {
  name: string;
  handler: (req: Request, res: Response, next: NextFunction) => unknown;
  priority: number;
}

// ============================================================================
// Security Config (using generic types to avoid circular deps)
// ============================================================================
export interface SecurityConfig {
  // Core security
  helmet?: boolean | Record<string, unknown>;
  cors?: boolean | Record<string, unknown>;
  rateLimit?: boolean | Record<string, unknown>;
  csrf?: boolean | Record<string, unknown>;
  
  // Advanced protection
  xss?: boolean | Record<string, unknown>;
  sqlInjection?: boolean | Record<string, unknown>;
  requestValidation?: boolean | Record<string, unknown>;
  securityHeaders?: boolean | Record<string, unknown>;
  
  // Deception & monitoring
  honeypot?: boolean | Record<string, unknown>;
  threatIntel?: boolean | Record<string, unknown>;
  anomalyDetection?: boolean | Record<string, unknown>;
  
  // Logging
  logging?: {
    level?: 'error' | 'warn' | 'info' | 'debug' | 'detailed';
    audit?: boolean;
    siem?: boolean;
  };
  
  // Mode
  strictMode?: boolean;
}

// ============================================================================
// Threat Data
// ============================================================================
export interface ThreatData {
  ip: string;
  score: number;
  type: string;
  timestamp: Date;
  metadata: Record<string, unknown>;
}

// ============================================================================
// Security Metrics
// ============================================================================
export interface SecurityMetrics {
  attacksBlocked: number;
  attacksDetected: number;
  honeypotInteractions: number;
  rateLimitHits: number;
  averageResponseTime: number;
}

// ============================================================================
// Deceptive Response
// ============================================================================
export interface DeceptiveResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
  delay?: number;
}

// ============================================================================
// Utility Types
// ============================================================================
export type SecurityPreset = 'basic' | 'api' | 'enterprise' | 'honeypot' | 'ecommerce' | 'development';
export type SecurityLevel = 'low' | 'medium' | 'high' | 'paranoid';
export type AttackType = 'xss' | 'sqli' | 'csrf' | 'rce' | 'lfi' | 'ddos';
