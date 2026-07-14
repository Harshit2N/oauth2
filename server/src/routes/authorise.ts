import { Router, Request, Response } from 'express';
import { requireAuth } from '../middleware/requireAuth';
import { revokeEveryUserToken } from '../lib/tokens';
const router = Router();
const revoke = async (req: Request, res: Response) => {
    const userId = req.user.sub
    if (req.body) {
        await revokeEveryUserToken(userId);
        return res.json({
            revoked: true,
            message: "Every session is revoked"
        })
    }
    await revokeEveryUserToken(userId);
    res.json({ reoked: true })
}
router.post('/', requireAuth, revoke);
export default router;