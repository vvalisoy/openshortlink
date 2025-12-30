// Validation utilities

import { z } from 'zod';

export function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export function isValidSlug(slug: string): boolean {
  // Alphanumeric, underscore, hyphen, 2-100 characters
  return /^[a-zA-Z0-9_-]{2,100}$/.test(slug);
}

// Reserved slugs that cannot be used for short links
const RESERVED_SLUGS = new Set([
  'api',
  'dashboard',
  'login',
  'setup',
  'assets',
  'health',
  'admin',
  'static',
  'auth',
  'logout',
  'register',
  'verify',
  'favicon.ico',
  'robots.txt',
  'sitemap.xml'
]);

export function isReservedSlug(slug: string): boolean {
  return RESERVED_SLUGS.has(slug.toLowerCase());
}

export function sanitizeSlug(slug: string): string {
  // Remove invalid characters, convert to lowercase
  return slug
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '')
    .replace(/^-+|-+$/g, '');
}

export function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    // Remove trailing slash from pathname
    if (parsed.pathname.length > 1 && parsed.pathname.endsWith('/')) {
      parsed.pathname = parsed.pathname.slice(0, -1);
    }
    return parsed.toString();
  } catch {
    return url;
  }
}

export function sanitizeHtml(input: unknown): string {
  try {
    // Handle edge cases: null, undefined, non-string types
    if (input === null || input === undefined) {
      return '';
    }
    
    const str = typeof input === 'string' ? input : String(input);
    
    // Proper HTML entity encoding to prevent XSS
    // Encode all HTML special characters
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  } catch (error) {
    // If anything goes wrong, return empty string and log error
    console.error('[sanitizeHtml] Error sanitizing input:', error);
    return '';
  }
}

export function sanitizeSearchInput(search: string): string {
  // Detect SQL injection patterns
  const sqlInjectionPatterns = [
    /('|(\-\-)|(;)|(\|\|)|(\*))/, // SQL special characters
    /(\bOR\b.*=.*)/i, // OR with equals
    /(\bAND\b.*=.*)/i, // AND with equals
    /(UNION.*SELECT)/i, // UNION SELECT
    /(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\s+(TABLE|DATABASE)/i, // DDL/DML
    /\/\*.*\*\//,  // SQL comments
  ];

  // Check for SQL injection patterns
  for (const pattern of sqlInjectionPatterns) {
    if (pattern.test(search)) {
      throw new Error('Invalid search input: potentially malicious pattern detected');
    }
  }

  // Return sanitized search (trim and limit length)
  return search.trim().substring(0, 200);
}

export function validateNumericBoundary(value: number, min: number, max: number, fieldName: string): number {
  if (!Number.isInteger(value) || !Number.isSafeInteger(value)) {
    throw new Error(`${fieldName} must be a safe integer`);
  }
  if (value < min || value > max) {
    throw new Error(`${fieldName} must be between ${min} and ${max}`);
  }
  return value;
}

// User management validation schemas
export const createUserSchema = z.object({
  username: z.string().min(3).max(50).regex(/^[a-zA-Z0-9_-]+$/, {
    message: 'Username can only contain letters, numbers, underscore, and hyphen'
  }),
  email: z.string().email().optional(),
  password: z.string()
    .min(12, { message: 'Password must be at least 12 characters long' })
    .regex(/[A-Z]/, { message: 'Password must contain at least one uppercase letter' })
    .regex(/[a-z]/, { message: 'Password must contain at least one lowercase letter' })
    .regex(/[0-9]/, { message: 'Password must contain at least one number' })
    .regex(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/, {
      message: 'Password must contain at least one special character (!@#$%^&*()_+-=[]{};\':"\\|,.<>/? etc.)'
    }),
  role: z.enum(['admin', 'user', 'analyst', 'owner']).default('user'),
  global_access: z.boolean().optional(),
  domain_ids: z.array(z.string()).optional(), // For specific domain access
});

export const updateUserSchema = z.object({
  username: z.string().min(3).max(50).regex(/^[a-zA-Z0-9_-]+$/).optional(),
  email: z.string().email().optional(),
  role: z.enum(['admin', 'user', 'analyst', 'owner']).optional(),
  global_access: z.boolean().optional(),
  domain_ids: z.array(z.string()).optional(), // For specific domain access
  preferences: z.record(z.string(), z.unknown()).optional(),
});

export const setUserDomainsSchema = z.object({
  global_access: z.boolean(),
  domain_ids: z.array(z.string()).optional(), // Required if global_access is false
}).refine(
  (data) => data.global_access || (data.domain_ids && data.domain_ids.length > 0),
  {
    message: 'domain_ids is required when global_access is false',
  }
);

