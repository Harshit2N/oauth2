import { Router, Request, Response } from 'express';
import { db } from '../db';
import { signAccessToken } from '../lib/jwt';
import { rotateRefreshToken } from '../lib/tokens';

const router = Router();

// ─── POST /token/refresh ─────────────────────────────────────────────────────
//
// Body: { refresh_token: '<opaque token>' }
//
// Server:
//   1. Finds the matching token by bcrypt-comparing against stored hashes
//   2. If already revoked → reuse detected → revoke entire family → 401
//   3. If valid → revoke old token, issue new refresh token (rotation)
//   4. Issue new access token
// ─────────────────────────────────────────────────────────────────────────────

router.post('/', async (req: Request, res: Response) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({
      error:   'invalid_request',
      message: 'refresh_token is required',
    });
  }

  const result = await rotateRefreshToken(refresh_token);

  if (!result) {
    return res.status(401).json({
      error:   'invalid_grant',
      message: 'Refresh token is invalid, expired, or has been revoked. Please log in again.',
    });
  }

  const user = await db.user.findUnique({ where: { id: result.userId } });
  if (!user) {
    return res.status(401).json({ error: 'invalid_grant', message: 'User not found' });
  }

  const accessToken = signAccessToken(user.id, user.email, result.scope);

  res.json({
    access_token:  accessToken,
    token_type:    'Bearer',
    expires_in:    900,
    refresh_token: result.newRaw,
    scope:         result.scope,
  });
});

export default router;
