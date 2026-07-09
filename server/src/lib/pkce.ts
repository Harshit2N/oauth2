import crypto from "crypto"

export const codeChallenge = ({ verifier }: { verifier: string }): string => {
    return crypto.createHash('sha256').update(verifier).digest('base64url');
}
export const verifyPKCE=({ verifier, storedChallenge }: { verifier: string, storedChallenge: string }): boolean =>{
    if (!verifier || !storedChallenge) return false;
    const result = codeChallenge({verifier});
    if (result.length !== storedChallenge.length) return false;
    return crypto.timingSafeEqual(Buffer.from(result), Buffer.from(storedChallenge))
}
export const generateVerifier=()=>{
    return crypto.randomBytes(32).toString('base64url');
}