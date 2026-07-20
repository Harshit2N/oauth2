import { Router, Request, Response } from "express";
import { db } from '../db'
import { generateToken } from "../lib/jwt";
import { requireAuth } from "../middleware/requireAuth";
import { hashPassword } from "../lib/password"
const router = Router();
router.get('/', requireAuth, async (req: Request, res: Response) => {
  const user = await db.user.findUnique({
    where: { id: req.user!.sub },
    select: { id: true, email: true, createdAt: true }
  })
  if (!user) {
    return res.status(400).json({
      error: "User not found",
      message: "User not found"
    })
  }
  res.json({
    sub: user.id,
    email: user.email,
    createdAt: user.createdAt,
    scope: req.user!.scope
  })
})
router.post('/register', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({
      error: "Invalid Request",
      message: "email and password required"
    })
  }
  if (password.length() < 8) {
    return res.status(400).json({
      error: "Invalid request",
      message: "Password length must be atleast 8"
    })
  }
  const existing = await db.user.findUnique({
    where: {
      email: email.toLowerCase()
    }
  })
  if (existing) {
    return res.status(400).json({
      error: "Invalid user",
      message: "User already exists"
    })
  }
  const hashedPassword = await hashPassword(password)
  const user = db.user.create({
    data: {
      email: email.toLowerCase(),
      passwordHash: hashedPassword,
    },
    select: {
      id: true,
      email: true,
      createdAt: true
    }
  })
  res.status(201).json({
    user
  })
})
export default router;
