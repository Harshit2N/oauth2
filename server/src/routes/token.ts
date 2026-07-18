
import { Router, Request, Response } from 'express';
import { redis } from '../lib/redis';
import { db } from '../db';
import { signAccessToken } from '../lib/jwt';
import { verifyPKCE } from '../lib/pkce';
import { issueRefreshToken } from '../lib/tokens';

const router = Router();

// ─── POST /token ─────────────────────────────────────────────────────────────
//
// Body: {
//   grant_type:    'authorization_code',
//   code:          '<auth code from /login redirect>',
//   code_verifier: '<original PKCE verifier>',
//   redirect_uri:  '<must match what was used in /authorize>',
//   client_id:     '<registered client ID>',
// }
//
// Server:
//   1. Pops the auth code from Redis (single-use — getDel)
//   2. Validates client_id + redirect_uri match what was stored
//   3. Verifies PKCE: SHA256(code_verifier) === stored code_challenge
//   4. Issues access token (JWT, 15m) + refresh token (opaque, 7d)
// ─────────────────────────────────────────────────────────────────────────────

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

  // 1. Pop auth code — single use (getDel = atomic get + delete)
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

  // 2. Validate client_id + redirect_uri haven't been tampered with
  //    (open redirect prevention)
  if (authCode.clientId !== client_id || authCode.redirectUri !== redirect_uri) {
    return res.status(400).json({
      error:   'invalid_grant',
      message: 'client_id or redirect_uri mismatch',
    });
  }

  // 3. Verify PKCE — this is the core security check
  if (!verifyPKCE(code_verifier, authCode.codeChallenge)) {
    return res.status(400).json({
      error:   'invalid_grant',
      message: 'PKCE verification failed',
    });
  }

  // 4. Fetch user
  const user = await db.user.findUnique({ where: { id: authCode.userId } });
  if (!user) {
    return res.status(400).json({ error: 'invalid_grant', message: 'User not found' });
  }

  // 5. Issue tokens
  const accessToken            = signAccessToken(user.id, user.email, authCode.scope);
  const { raw: refreshToken }  = await issueRefreshToken(user.id, authCode.scope);

  res.json({
    access_token:  accessToken,
    token_type:    'Bearer',
    expires_in:    900,           // 15 minutes
    refresh_token: refreshToken,
    scope:         authCode.scope,
  });
});

export default router;
