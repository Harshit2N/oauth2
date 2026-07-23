import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { redis } from '../lib/redis';
import { db } from '../db';
import { verifyPassword } from '../lib/password';

const router = Router();

router.post('/', async (req: Request, res: Response) => {
  const { email, password, requestId } = req.body;

  if (!email || !password || !requestId) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'email, password, and requestId are required',
    });
  }

  const stored = await redis.get(`auth_request:${requestId}`);

  if (!stored) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Authorization request not found or expired',
    });
  }

  const authRequest = JSON.parse(stored) as {
    clientId: string;
    redirectUri: string;
    state: string;
    scope: string;
    codeChallenge: string;
  };

  const user = await db.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  const isValid = user
    ? await verifyPassword(password, user.passwordHash)
    : await fakeVerify();

  if (!isValid || !user) {
    return res.status(401).json({
      error: 'invalid_credentials',
      message: 'Email or password is incorrect',
    });
  }

  const code = crypto.randomBytes(32).toString('base64url');

  await redis.del(`auth_request:${requestId}`);

  await redis.setEx(
    `auth_code:${code}`,
    300,
    JSON.stringify({
      userId: user.id,
      clientId: authRequest.clientId,
      redirectUri: authRequest.redirectUri,
      scope: authRequest.scope,
      codeChallenge: authRequest.codeChallenge,
    })
  );

  const redirectUrl = new URL(authRequest.redirectUri);
  redirectUrl.searchParams.set('code', code);
  redirectUrl.searchParams.set('state', authRequest.state);

  res.json({
    redirectUrl: redirectUrl.toString(),
  });
});

async function fakeVerify(): Promise<false> {
  const { hashPassword } = await import('../lib/password');
  await hashPassword('fake-password-for-timing');
  return false;
}

export default router;