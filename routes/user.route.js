const {registeruser , loginuser, userCredits} = require('../controllers/user.controller')
const express = require('express')
const { userAuth } = require('../middlewares/auth')

const userRouter = express.Router()

userRouter.post('/register', registeruser)
//localhost:4000/api/user/register


//localhost:4000/api/user/login
userRouter.post('/login',loginuser)

userRouter.get('/credit',userAuth,userCredits)

module.exports = userRouter;