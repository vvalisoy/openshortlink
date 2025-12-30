// Settings API endpoints

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import type { Env } from '../types';
import { authMiddleware } from '../middleware/auth';
import {
  getStatusCheckFrequency,
  setStatusCheckFrequency,
  getStatusCheckFrequencyOrDefault,
  getAnalyticsAggregationEnabled,
  getAnalyticsAggregationEnabledOrDefault,
  setAnalyticsAggregationEnabled,
  getAnalyticsThresholds,
  getAnalyticsThresholdsOrDefault,
  setAnalyticsThresholds,
} from '../db/settings';
import { getFrequencyLabel } from '../types';

const settingsRouter = new Hono<{ Bindings: Env }>();

// Validation schema
const statusCheckFrequencySchema = z.object({
  frequency: z.object({
    value: z.number().int().min(1).max(365),
    unit: z.enum(['days', 'weeks']),
  }),
  enabled: z.boolean(),
  check_top_100_daily: z.boolean(),
  batch_size: z.number().int().min(10).max(1000).default(100),
});

// Get status check frequency setting
settingsRouter.get('/status-check-frequency', authMiddleware, async (c) => {
  const user = c.get('user');
  
  // Only admin/owner can view settings
  if (user.role !== 'admin' && user.role !== 'owner') {
    throw new HTTPException(403, { message: 'Insufficient permissions' });
  }

  const setting = await getStatusCheckFrequencyOrDefault(c.env);

  return c.json({
    success: true,
    data: {
      ...setting,
      frequency_label: getFrequencyLabel(setting.frequency),
    },
  });
});

// Update status check frequency setting
settingsRouter.put('/status-check-frequency', authMiddleware, async (c) => {
  const user = c.get('user');
  
  // Only admin/owner can update settings
  if (user.role !== 'admin' && user.role !== 'owner') {
    throw new HTTPException(403, { message: 'Insufficient permissions' });
  }

  const body = await c.req.json();
  const validated = statusCheckFrequencySchema.parse(body);

  await setStatusCheckFrequency(
    c.env,
    validated.frequency,
    validated.enabled,
    validated.check_top_100_daily,
    validated.batch_size,
    user.id
  );

  const updated = await getStatusCheckFrequency(c.env);

  return c.json({
    success: true,
    data: {
      ...updated!,
      frequency_label: getFrequencyLabel(validated.frequency),
    },
    message: 'Status check frequency updated successfully',
  });
});

// Analytics Aggregation Settings

// Get analytics aggregation enabled setting
settingsRouter.get('/analytics-aggregation', authMiddleware, async (c) => {
  const user = c.get('user');
  
  // Only admin/owner can view settings
  if (user.role !== 'admin' && user.role !== 'owner') {
    throw new HTTPException(403, { message: 'Insufficient permissions' });
  }

  const setting = await getAnalyticsAggregationEnabledOrDefault(c.env);

  return c.json({
    success: true,
    data: setting,
  });
});

// Update analytics aggregation enabled setting
settingsRouter.put('/analytics-aggregation', authMiddleware, async (c) => {
  const user = c.get('user');
  
  // Only admin/owner can update settings
  if (user.role !== 'admin' && user.role !== 'owner') {
    throw new HTTPException(403, { message: 'Insufficient permissions' });
  }

  const body = await c.req.json();
  const validated = z.object({
    enabled: z.boolean(),
  }).parse(body);

  await setAnalyticsAggregationEnabled(
    c.env,
    validated.enabled,
    user.id
  );

  const updated = await getAnalyticsAggregationEnabled(c.env);

  return c.json({
    success: true,
    data: updated || await getAnalyticsAggregationEnabledOrDefault(c.env),
    message: `Analytics aggregation ${validated.enabled ? 'enabled' : 'disabled'} successfully`,
  });
});

// Get analytics thresholds
settingsRouter.get('/analytics-thresholds', authMiddleware, async (c) => {
  const user = c.get('user');
  
  // Only admin/owner can view settings
  if (user.role !== 'admin' && user.role !== 'owner') {
    throw new HTTPException(403, { message: 'Insufficient permissions' });
  }

  const thresholds = await getAnalyticsThresholdsOrDefault(c.env);

  return c.json({
    success: true,
    data: thresholds,
  });
});

// Update analytics thresholds
settingsRouter.put('/analytics-thresholds', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    
    // Only admin/owner can update settings
    if (user.role !== 'admin' && user.role !== 'owner') {
      throw new HTTPException(403, { message: 'Insufficient permissions' });
    }

    const body = await c.req.json();
    const validated = z.object({
      threshold_days: z.number().int().min(1).max(90),
    }).parse(body);

    await setAnalyticsThresholds(
      c.env,
      validated.threshold_days,
      user.id
    );

    const updated = await getAnalyticsThresholds(c.env);

    return c.json({
      success: true,
      data: updated || await getAnalyticsThresholdsOrDefault(c.env),
      message: 'Analytics thresholds updated successfully',
    });
  } catch (error) {
    console.error('[SETTINGS] Update analytics thresholds error:', error);
    // Re-throw HTTPException and ZodError for error handler
    if (error instanceof HTTPException) {
      throw error;
    }
    // Handle database errors
    if (error instanceof Error && error.message.includes('UNIQUE constraint')) {
      throw new HTTPException(409, { message: 'Duplicate settings entry' });
    }
    throw new HTTPException(500, { 
      message: error instanceof Error ? error.message : 'Failed to update analytics thresholds' 
    });
  }
});

export { settingsRouter };

