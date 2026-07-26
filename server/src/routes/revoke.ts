import { Router, Request, Response } from 'express';
import { requireAuth } from '../middleware/requireAuth';
import { revokeAllUserTokens } from '../lib/tokens';

const router = Router();
router.post('/', requireAuth, async (req: Request, res: Response) => {
  const userId = req.user!.sub;
  const { all } = req.body;

  if (all) {
    await revokeAllUserTokens(userId);
    return res.json({ revoked: true, message: 'All sessions revoked' });
  }

  await revokeAllUserTokens(userId);
  res.json({ revoked: true });
});

export default router;
