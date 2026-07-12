import { Request,Response,NextFunction } from "express";
import {db} from '../db'
export const validateClient=async (req:Request,res:Response,next:NextFunction):Promise<void>=>{
    const id=req.query.clientId as string | undefined
    const uri=req.query.redirectUri as string | undefined
    if(!id){
        res.status(400).json({
            error:"invalid request",
            message:"client id is required"
        })
        return
    }
    const client= await db.oAuthClient.findUnique({where:{id:id}});
    if(!client){
        res.status(400).json({
            error:"invalid client",
            message:"unknown client id"
        })
        return
    }
    if(uri && !client.redirectUris.includes(uri)){
        res.status(400).json({
            error:"invalid request",
            message:"redirect is not registered for the client"
        })
        return
    }
    (req as any).oAuthClient=client;
    next();
}