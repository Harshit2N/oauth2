import 'dotenv/config';
import express from 'express';
import cors from 'cors';

import authorizeRouter from './routes/authorize';
import loginRouter from './routes/login';
import tokenRouter from './routes/token';
import refreshRouter from './routes/refresh';
import revokeRouter from './routes/revoke';
import userinfoRouter from './routes/userinfo';

const app = express();
const PORT = Number(process.env.PORT ?? 3001);

app.use(cors({
  origin: process.env.CLIENT_ORIGIN ?? 'http://localhost:5173',
  methods: ['GET', 'POST', 'DELETE'],
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

app.get('/health', (_req, res) =>
  res.json({ status: 'ok', uptime: process.uptime() })
);

app.use('/authorize', authorizeRouter);
app.use('/login', loginRouter);
app.use('/token', tokenRouter);
app.use('/token/refresh', refreshRouter);
app.use('/token/revoke', revokeRouter);

app.use('/userinfo', userinfoRouter);
app.post('/register', userinfoRouter);

app.listen(PORT, () => {
  console.log(`\n[Auth Server] Running at http://localhost:${PORT}`);
  console.log('[Auth Server] Endpoints:');
  console.log('  GET  /authorize');
  console.log('  POST /login');
  console.log('  POST /token');
  console.log('  POST /token/refresh');
  console.log('  POST /token/revoke');
  console.log('  GET  /userinfo');
  console.log('  POST /register\n');
});

export default app;