
import {Request,Response,NextFunction} from 'express'
import {Payload,verifyToken} from '../lib/jwt'

declare global{
    namespace Express{
        interface Request{
            user?:Payload
        }
    }
}
export const requireAuth=(req:Request,res:Response,next:NextFunction):void=>{
        try{
            const header=req.headers.authorization
            if(!header||!header.startsWith('Bearer ')){
                res.status(401).json({
                    error:'Unauthorized',
                    message:"Missing Bearer Token"
                })
                return;
            }
            const token=header.slice(7)
            req.user=verifyToken(token)
            next()
        }catch(error:unknown){
            res.status(401).json({
                error:"Unauthorized",
                message:"Invalid Token"
            })
        }   
}