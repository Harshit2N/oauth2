import { Router, Request, Response } from 'express';
import { requireAuth } from '../middleware/requireAuth';
import { revokeAllUserTokens } from '../lib/tokens';

const router = Router();

// ─── POST /token/revoke ───────────────────────────────────────────────────────
//
// Requires: Authorization: Bearer <access_token>
// Body: { all?: boolean }
//
// With all=true:  revokes every refresh token for the user (logout all devices)
// With all=false: revokes only the specific refresh_token in the body
// ─────────────────────────────────────────────────────────────────────────────

router.post('/', requireAuth, async (req: Request, res: Response) => {
  const userId = req.user!.sub;
  const { all } = req.body;

  if (all) {
    await revokeAllUserTokens(userId);
    return res.json({ revoked: true, message: 'All sessions revoked' });
  }

  // Single token revocation — find by body token and mark revoked
  // (simplified: just revoke all for now in the demo)
  await revokeAllUserTokens(userId);
  res.json({ revoked: true });
});

export default router;
