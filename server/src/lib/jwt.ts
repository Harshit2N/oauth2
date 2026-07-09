import jwt from "jsonwebtoken"
import { v4 as uuid } from "uuid"
import dotenv from "dotenv"

dotenv.config()
const secret = process.env.JWT_SECRET
if (!secret) {
    throw new Error("secret not defined");
}
interface Payload {
    userId: string;
    email: string
    scope: string;
}
export const generateToken = (payload: Payload): string => {
    return jwt.sign(payload, secret, {
        issuer: "my-server",
        jwtid: uuid(),
        expiresIn: "15m",
        algorithm: "HS256"
    });
}
export const verifyToken = (payload: string): Payload => {
    return jwt.verify(payload, secret, { issuer: "my-server" }) as Payload;
}