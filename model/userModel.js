import mongoose, {model, Schema } from "mongoose";
import JWT from "jsonwebtoken";
import bcrypt  from 'bcrypt';
import crypto from 'crypto';


const userSchema = new Schema({
    userName:{
        type:String,
        trim:true,
    },
    email:{
        type:String,
        trim:true,
        requied:[true,"Email is a must"]
    },
    password:{
        type:String,
        trim:true,
        select:false,
        requied:[true,"Password is a must"]
    },
    confirmPassword:{
        type:String
    },
    avatar: {
        public_id: {
          type: String,
        },
        secure_url: {
          type: String,
        }
    },
    role: {
        type: String,
        enum: ['USER', 'ADMIN'],
        default: 'USER',
      },
    forgotPasswordToken: String,
    forgotPasswordExpiry: Date
});

userSchema.pre('save',async function(next) {
    if (!this.isModified ('password') ) {
        next();
    }

    this.password = await bcrypt.hash(this.password,10);
    return next();
})

userSchema.methods = {
    jwtToken () {
        return JWT.sign (
            {id:this._id,email:this.email},
            process.env.SECRET,
            {expiresIn: '24h'}
        )
    },

    generateResetPasswordToken : async function () {

        const resetToken = crypto.randomBytes(20).toString('hex');

        this.forgotPasswordToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex')

        this.forgotPasswordExpiry = Date.now() + 15*60*1000;

        return resetToken

    }
}

const User = mongoose.model('User', userSchema)

export default User;