import { Router } from "express";
import { changePassword, forgotPassword, logOut, registration, resetPassword, signIn, updateUser, userDetails } from "../controller/userController.js";
import { jwtAuth } from "../middleware/jwtAuth.js";
import upload from "../middleware/multer.middleware.js";

const router = Router();

router.get("/",((req,res)=> {
    try {
        res.status(200).json({
            success:true,
            message:"Welcome to user management system"
        })
    } catch (error) {
        return res.status(404).json({
            success:false,
            message:`Internal server error ${error.message}`
        })
    }
}))

router.post('/signup',upload.single("avatar"),registration)
router.post('/signin',signIn)
router.get('/user',jwtAuth,userDetails)
router.get('/logout',jwtAuth,logOut)
router.post('/reset',forgotPassword)
router.post('/reset/:resetToken',resetPassword)
router.post('/changePassword',jwtAuth,changePassword)
router.put('/update',jwtAuth,upload.single("avatar"),updateUser)

export default router;