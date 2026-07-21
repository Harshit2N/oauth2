import { Router, Request, Response } from 'express';
import { v4 as uuid } from 'uuid';
import { redis } from '../lib/redis';
import { validateClient } from '../middleware/validateClient';

const router = Router();

router.get('/', validateClient, async (req: Request, res: Response) => {
  const {
    response_type,
    state,
    scope,
    code_challenge,
    code_challenge_method,
  } = req.query as Record<string, string>;

  const { redirect_uri, id: clientId } = (req as any).oauthClient;

  if (response_type !== 'code') {
    return res.status(400).json({
      error: 'unsupported_response_type',
      message: 'Only response_type=code is supported',
    });
  }

  if (code_challenge_method !== 'S256' || !code_challenge) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'PKCE with code_challenge_method=S256 is required',
    });
  }

  if (!state) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'state parameter is required (CSRF protection)',
    });
  }

  const requestId = uuid();

  await redis.setEx(
    `auth_request:${requestId}`,
    300,
    JSON.stringify({
      clientId,
      redirectUri: req.query.redirect_uri as string,
      state,
      scope: scope ?? 'openid',
      codeChallenge: code_challenge,
    })
  );

  res.json({
    requestId,
    message: 'Proceed to POST /login with email, password, and requestId',
  });
});

export default router;