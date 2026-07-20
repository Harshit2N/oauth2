import jwt from "jsonwebtoken"
import { v4 as uuid } from "uuid"
import dotenv from "dotenv"
dotenv.config()
const SECRET = process.env.JWT_SECRET
const ISSUER = 'server'
if (!SECRET) {
    throw new Error("secret not defined");
}
export interface Payload{
    sub: string
    email: string
    scope: string
    jti: string
    iss: number
    iat: number
    exp: number
}
export const generateToken = (userId: string, email: string, scope: string): string => {
    return jwt.sign(
       { sub: userId, email, scope, jti: uuid(), iss: ISSUER },
        SECRET,
        { expiresIn: '15m', algorithm: 'HS256' }
    )
}
export const verifyToken = (token: string): Payload => {
    const decoded= jwt.verify(token, SECRET, { issuer: ISSUER});
    if(typeof decoded==="string"){
        throw new Error("Invalid token Payload");
    }
    return decoded as unknown as Payload
}