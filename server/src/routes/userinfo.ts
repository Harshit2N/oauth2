import { Router, Request, Response } from 'express';
import { db } from '../db';
import { hashPassword } from '../lib/password';
import { requireAuth } from '../middleware/requireAuth';

const router = Router();

// ─── GET /userinfo ────────────────────────────────────────────────────────────
// Protected resource — requires valid access token
router.get('/', requireAuth, async (req: Request, res: Response) => {
  const user = await db.user.findUnique({
    where:  { id: req.user!.sub },
    select: { id: true, email: true, createdAt: true },
  });

  if (!user) {
    return res.status(404).json({ error: 'not_found' });
  }

  res.json({
    sub:        user.id,
    email:      user.email,
    created_at: user.createdAt,
    scope:      req.user!.scope,
  });
});

// ─── POST /register ────────────────────────────────────────────────────────────
// Creates a new user account (public endpoint for the demo)
router.post('/register', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'invalid_request', message: 'email and password required' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'invalid_request', message: 'Password must be at least 8 characters' });
  }

  const existing = await db.user.findUnique({ where: { email: email.toLowerCase() } });
  if (existing) {
    return res.status(409).json({ error: 'conflict', message: 'Email already registered' });
  }

  const user = await db.user.create({
    data: {
      email:        email.toLowerCase(),
      passwordHash: await hashPassword(password),
    },
    select: { id: true, email: true, createdAt: true },
  });

  res.status(201).json({ user });
});

export default router;
