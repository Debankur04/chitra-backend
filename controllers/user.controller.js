const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');
const userModel = require('../model/user.model');


module.exports.registeruser = async (req,res)=>{
    try{
        const {name , email, password} = req.body;
        if(!name || !email || !password){
            return res.json({success: false, message: 'Missing Details'})
        }

        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password,salt)

        const userData = {
            name, email, password : hashedPassword
        }

        const newuser = new userModel(userData)
        const user = await newuser.save()

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET)

        res.json({success: true, token, user: {name: user.name}})

    }catch(error){
        console.log(error);
        res.json({success: false,  message: error.message})
    }
}

module.exports.loginuser = async(req,res)=>{
    try {
        const {email, password} = req.body
        const user = await userModel.findOne({email})

        if(!user){
            return res.json({success: false, message: 'Missing/Wrong Details'})
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if(isMatch){

            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
            res.json({success: true, token, user: {name: user.name}})

        }else{
            return res.json({success: false, message: 'User does not exist'})
        }
    } catch (error) {
        console.log(error);
        res.json({success: false,  message: error.message})
    }
}


module.exports.userCredits = async (req,res) => {
    try {
        const userId = req.userId; // ✅ This works — set by the middleware
        const user = await userModel.findById(userId)
        res.json({success: true, credits: user.creditBalance, user: {name: user.name}})
    } catch (error) {
        console.log(error.message);
        res.json({success:false, message: error.message})
    }
}