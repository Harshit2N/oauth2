import 'dotenv/config';
import { db } from '../db';
import { hashPassword } from '../lib/password';
import bcrypt from 'bcrypt';

async function main() {
  console.log('Seeding OAuth2 demo data...\n');

  const clientSecret = 'demo-client-secret';
  const secretHash = await bcrypt.hash(clientSecret, 10);

  await db.oAuthClient.upsert({
    where: { id: 'demo-spa' },
    update: {},
    create: {
      id: 'demo-spa',
      secretHash,
      name: 'Demo SPA',
      redirectUris: [
        'http://localhost:5173/callback',
        'http://localhost:3000/callback',
      ],
      scopes: ['openid', 'profile', 'email'],
    },
  });

  console.log('✓ OAuth client registered: demo-spa');
  console.log('  client_id:     demo-spa');
  console.log('  redirect_uri:  http://localhost:5173/callback\n');

  await db.user.upsert({
    where: { email: 'harshit@example.com' },
    update: {},
    create: {
      email: 'harshit@example.com',
      passwordHash: await hashPassword('password123'),
    },
  });

  console.log('✓ Test user created:');
  console.log('  email:    harshit@example.com');
  console.log('  password: password123\n');

  console.log('Start the server with: npm run dev');
  console.log('Then open the React client at: http://localhost:5173\n');

  process.exit(0);
}

main().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});