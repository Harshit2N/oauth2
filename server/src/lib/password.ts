import bcrypt from "bcrypt"

const salt: number = 12;

const hashPassword = async ({ password }: { password: string }): Promise<string> => {
    return await bcrypt.hash(password, salt);
}

const verfiyPassword = async ({ password, hashPassword }: { password: string; hashPassword: string }): Promise<boolean> => {
    return await bcrypt.compare(password, hashPassword);
}