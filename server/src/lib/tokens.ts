import crypto from "crypto"
import bcrypt from "bcrypt"
import { v4 as uuid } from 'uuid'
import { db } from '../db'

const day = 7, salt = 10;

export const issueRefreshToken = async ({ userId, scope, family=uuid() }: { userId: string, scope: string, family?: string }): Promise<{ raw: string, family: string }> => {
    const raw = crypto.randomBytes(40).toString('base64url');
    const hash = await bcrypt.hash(raw, salt);
    await db.refreshToken.create({
        data: {
            tokenHash: hash,
            userId,
            scope,
            family,
            expiresAt: new Date(Date.now() + day * 86_400_000)
        }
    });
    return { raw, family }
}

export const rotateRefreshToken = async ({ raw }: { raw: string }): Promise<{
    newRaw: string;
    userId: string;
    scope: string;
    family: string;
} | null>=>{
    const candidate = await db.refreshToken.findMany({
        where: {
            expiresAt: { gt: new Date() },
        },
        orderBy: {
            createdAt: 'desc'
        },
        take: 200
    })
    let matched: (typeof candidate)[0] | null = null
    for (const c of candidate) {
        if (await bcrypt.compare(raw, c.tokenHash)) {
            matched = c
            break;
        }
    }
    if (!matched) return null;
    if (matched.revokedAt !== null) {
        console.warn('Refresh token reuse detected');
        await db.refreshToken.updateMany({
            where: { family: matched.family },
            data: { revokedAt: new Date() }
        })
        return null;
    }
    const { raw: newRaw } = await issueRefreshToken({userId:matched.userId, scope:matched.scope, family:matched.family});
    await db.refreshToken.update({
        where: { id: matched.id },
        data: { revokedAt: new Date() }
    })
    return {
        newRaw:newRaw,
        userId: matched.userId,
        scope: matched.scope,
        family: matched.family
    }
}

export const revokeEveryUserToken = async ({userId}: {userId:string}): Promise<void>=>{
    await db.refreshToken.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date() }
    })
}