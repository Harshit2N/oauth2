import { createClient } from 'redis';

const REDIS_URL = process.env.REDIS_URL ?? 'redis://localhost:6379';

export const redis = createClient({ url: REDIS_URL });

redis.on('error',       (err) => console.error('[Redis] Error:', err.message));
redis.on('connect',     ()    => console.log('[Redis] Connected'));
redis.on('reconnecting',()    => console.log('[Redis] Reconnecting...'));

redis.connect().catch((err) => {
  console.error('[Redis] Failed to connect on startup:', err.message);
  process.exit(1);
});
