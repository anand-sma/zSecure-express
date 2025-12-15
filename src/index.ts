/**
 * zSecure-express - Enterprise Security Middleware for Express.js
 * 
 * @packageDocumentation
 * @module zsecure-express
 */

// ============================================================================
// Core Types
// ============================================================================
export type {
  SecurityConfig,
  MiddlewareChain,
  ThreatData,
  SecurityMetrics,
  DeceptiveResponse,
  SecurityPreset,
  SecurityLevel,
  AttackType
} from './types';

// ============================================================================
// Utilities
// ============================================================================
export { 
  encryption, 
  type EncryptedPayload 
} from './utils/encryption';

export { 
  jwt, 
  jwtUtils,
  type JwtSignOptions,
  type JwtVerifyOptions
} from './utils/jwt-enhanced';

export { 
  logger, 
  type Logger,
  type LogLevel
} from './utils/logger';

// ============================================================================
// Configuration
// ============================================================================
export { presets } from './config/presets';

// ============================================================================
// Main Security Wrapper
// ============================================================================
export { SecurityWrapper, secure } from './middleware/core/security-wrapper';

// ============================================================================
// Core Middleware
// ============================================================================
export { 
  createHelmetMiddleware as helmet, 
  type HelmetOptions 
} from './middleware/core/helmet-enhanced';

export { 
  createRateLimitMiddleware as rateLimit, 
  type RateLimitOptions, 
  type RateLimitLogger 
} from './middleware/core/rate-limiting';

export { 
  createCsrfMiddleware as csrf, 
  type CsrfOptions, 
  type CsrfLogger 
} from './middleware/core/csrf-protection';

export { 
  createCorsMiddleware as cors, 
  type CorsOptions, 
  type CorsLogger,
  type StaticOrigin,
  type CustomOriginCallback
} from './middleware/core/cors-protection';

export { 
  createRequestValidationMiddleware as requestValidation, 
  type RequestValidationOptions, 
  type ValidationLogger 
} from './middleware/core/request-validation';

export { 
  createSecurityHeadersMiddleware as securityHeaders, 
  type SecurityHeadersOptions 
} from './middleware/core/security-headers';

// ============================================================================
// Advanced Middleware
// ============================================================================
export { 
  createXSSMiddleware as xss, 
  type XSSOptions, 
  type XSSLogger 
} from './middleware/advanced/xss-protection';

export { 
  createSQLInjectionMiddleware as sqlInjection, 
  type SQLInjectionOptions, 
  type SQLInjectionLogger 
} from './middleware/advanced/sql-injection';

export { 
  createThreatIntelMiddleware as threatIntelligence, 
  type ThreatIntelOptions, 
  type ThreatIntelLogger, 
  type ThreatProvider, 
  type ThreatScore 
} from './middleware/advanced/threat-intel';

export { 
  createAnomalyDetectionMiddleware as anomalyDetection, 
  type AnomalyOptions, 
  type AnomalyLogger, 
  type ClientProfile 
} from './middleware/advanced/anomaly-detection';

// ============================================================================
// Deception Middleware
// ============================================================================
export { 
  createHoneypotMiddleware as honeywall, 
  type HoneywallOptions, 
  type HoneywallLogger 
} from './middleware/deception/honeywall';

// ============================================================================
// Plugin System
// ============================================================================
export { 
  PluginManager,
  AuditLogPlugin,
  SimpleWafPlugin,
  makeIpAllowlistPlugin,
  type SecurityPlugin,
  type PluginContext,
  type PluginLogger
} from './plugins';