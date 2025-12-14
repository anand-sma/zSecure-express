/**
 * Global type augmentations for Express Request interface.
 * Adds security-specific properties used by zSecure middlewares.
 */

import 'express';

declare module 'express' {
  interface Request {
    /** Unique request ID for correlation (set by audit logging) */
    id?: string;
    /** Parsed cookies (if cookie-parser or manual parsing is used) */
    cookies?: Record<string, string>;
    /** Security context populated by zSecure middlewares */
    security?: {
      score?: number;
      threatLevel?: 'low' | 'medium' | 'high' | 'critical';
      blocked?: boolean;
      violations?: string[];
    };
  }
}
