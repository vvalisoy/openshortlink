// Tags API endpoints

import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import type { Env, User } from '../types';
import { listTags, countTags, getTagById, createTag, updateTag, deleteTag } from '../db/tags';
import { getDomainById } from '../db/domains';
import { authMiddleware } from '../middleware/auth';
import { createRateLimit } from '../middleware/rateLimit';
import { requirePermission } from '../middleware/authorization';
import { filterTagsByAccess, canAccessDomain } from '../utils/permissions';

const tagsRouter = new Hono<{ Bindings: Env }>();

const createTagSchema = z.object({
  name: z.string().min(1).max(50),
  domain_id: z.string().optional(),
  color: z.string().regex(/^#[0-9A-Fa-f]{6}$/).optional(),
});

const updateTagSchema = z.object({
  name: z.string().min(1).max(50).optional(),
  color: z.string().regex(/^#[0-9A-Fa-f]{6}$/).optional(),
});

// List tags
tagsRouter.get('/', authMiddleware, async (c) => {
  const domainId = c.req.query('domain_id');
  const limitParam = c.req.query('limit');
  const offsetParam = c.req.query('offset');

  // Validate and set limit (default 25, max 500)
  const limit = limitParam ? Math.min(Math.max(parseInt(limitParam) || 25, 1), 500) : 25;
  const offset = offsetParam ? Math.max(parseInt(offsetParam) || 0, 0) : 0;

  let tags = await listTags(c.env, {
    domainId: domainId || undefined,
    limit: 10000, // Get all for filtering
    offset: 0,
  });

  // Filter by user's domain access
  const user = c.get('user') as User;
  // Use cached accessible_domain_ids from context (already fetched in authMiddleware)
  const accessibleDomainIds = (user as any).accessible_domain_ids;
  tags = await filterTagsByAccess(c.env, tags, user, accessibleDomainIds);

  // Apply pagination after filtering
  const totalCount = tags.length;
  tags = tags.slice(offset, offset + limit);

  return c.json({
    success: true,
    data: tags,
    pagination: {
      limit,
      offset,
      count: tags.length,
      total: totalCount,
      hasMore: offset + limit < totalCount,
    },
  });
});

// Get tag by ID
tagsRouter.get('/:id', authMiddleware, async (c) => {
  const id = c.req.param('id');
  const tag = await getTagById(c.env, id);

  if (!tag) {
    throw new HTTPException(404, { message: 'Tag not found' });
  }

  // Check domain access if tag has a domain
  if (tag.domain_id) {
    const user = c.get('user') as User;
    const hasAccess = await canAccessDomain(c.env, user, tag.domain_id);
    if (!hasAccess) {
      throw new HTTPException(403, { message: 'Access denied. You do not have access to this domain.' });
    }
  }

  return c.json({ success: true, data: tag });
});

// Create tag
tagsRouter.post('/', authMiddleware, requirePermission('manage_tags'), createRateLimit({
  window: 60,
  max: 50,
  key: 'tag:create',
}), async (c) => {
  const body = await c.req.json();
  const validated = createTagSchema.parse(body);

  // Validate domain exists if domain_id is provided
  if (validated.domain_id) {
    const domain = await getDomainById(c.env, validated.domain_id);
    if (!domain) {
      throw new HTTPException(404, { message: 'Domain not found' });
    }

    // Check domain access
    const user = c.get('user') as User;
    const hasAccess = await canAccessDomain(c.env, user, validated.domain_id);
    if (!hasAccess) {
      throw new HTTPException(403, { message: 'Access denied. You do not have access to this domain.' });
    }
  }

  // Check if tag already exists for this domain
  const existingTags = await listTags(c.env, { domainId: validated.domain_id });
  if (existingTags.some(t => t.name.toLowerCase() === validated.name.toLowerCase())) {
    throw new HTTPException(409, { message: 'Tag already exists' });
  }

  const tag = await createTag(c.env, validated);

  return c.json({ success: true, data: tag }, 201);
});

// Update tag
tagsRouter.put('/:id', authMiddleware, requirePermission('manage_tags'), async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();
  const validated = updateTagSchema.parse(body);

  const existingTag = await getTagById(c.env, id);
  if (!existingTag) {
    throw new HTTPException(404, { message: 'Tag not found' });
  }

  // Check domain access if tag has a domain
  if (existingTag.domain_id) {
    const user = c.get('user') as User;
    const hasAccess = await canAccessDomain(c.env, user, existingTag.domain_id);
    if (!hasAccess) {
      throw new HTTPException(403, { message: 'Access denied. You do not have access to this domain.' });
    }
  }

  const tag = await updateTag(c.env, id, validated);

  return c.json({ success: true, data: tag });
});

// Delete tag
tagsRouter.delete('/:id', authMiddleware, requirePermission('manage_tags'), async (c) => {
  const id = c.req.param('id');

  const existingTag = await getTagById(c.env, id);
  if (!existingTag) {
    throw new HTTPException(404, { message: 'Tag not found' });
  }

  // Check domain access if tag has a domain
  if (existingTag.domain_id) {
    const user = c.get('user') as User;
    const hasAccess = await canAccessDomain(c.env, user, existingTag.domain_id);
    if (!hasAccess) {
      throw new HTTPException(403, { message: 'Access denied. You do not have access to this domain.' });
    }
  }

  await deleteTag(c.env, id);

  return c.json({ success: true, message: 'Tag deleted successfully' });
});

export { tagsRouter };

