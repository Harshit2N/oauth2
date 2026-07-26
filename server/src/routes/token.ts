
import { Router, Request, Response } from 'express';
import { redis } from '../lib/redis';
import { db } from '../db';
import { signAccessToken } from '../lib/jwt';
import { verifyPKCE } from '../lib/pkce';
import { issueRefreshToken } from '../lib/tokens';

const router = Router();

router.post('/', async (req: Request, res: Response) => {
  const { grant_type, code, code_verifier, redirect_uri, client_id } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({
      error:   'unsupported_grant_type',
      message: 'Only authorization_code grant is supported here',
    });
  }

  if (!code || !code_verifier || !redirect_uri || !client_id) {
    return res.status(400).json({
      error:   'invalid_request',
      message: 'code, code_verifier, redirect_uri, and client_id are all required',
    });
  }
  const stored = await redis.getDel(`auth_code:${code}`);
  if (!stored) {
    return res.status(400).json({
      error:   'invalid_grant',
      message: 'Authorization code is invalid, expired, or already used',
    });
  }

  const authCode = JSON.parse(stored) as {
    userId:        string;
    clientId:      string;
    redirectUri:   string;
    scope:         string;
    codeChallenge: string;
  };

  if (authCode.clientId !== client_id || authCode.redirectUri !== redirect_uri) {
    return res.status(400).json({
      error:   'invalid_grant',
      message: 'client_id or redirect_uri mismatch',
    });
  }
  if (!verifyPKCE(code_verifier, authCode.codeChallenge)) {
    return res.status(400).json({
      error:   'invalid_grant',
      message: 'PKCE verification failed',
    });
  }

  const user = await db.user.findUnique({ where: { id: authCode.userId } });
  if (!user) {
    return res.status(400).json({ error: 'invalid_grant', message: 'User not found' });
  }

  const accessToken            = signAccessToken(user.id, user.email, authCode.scope);
  const { raw: refreshToken }  = await issueRefreshToken(user.id, authCode.scope);

  res.json({
    access_token:  accessToken,
    token_type:    'Bearer',
    expires_in:    900,         
    refresh_token: refreshToken,
    scope:         authCode.scope,
  });
});

export default router;
