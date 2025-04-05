const express = require('express')
const cors = require('cors')
require("dotenv").config();
const connectDB = require('./config/mongodb');
const userRouter = require('./routes/user.route');
const imageRouter = require('./routes/image.route');

const PORT = process.env.PORT || 4000
const app = express()

app.use(express.json())
app.use(cors())
connectDB()


app.use('/api/user' ,userRouter)

app.use('/api/image' ,imageRouter)


app.get('/',(req,res)=>{
    res.send('Hello world')
})

app.listen(PORT , ()=> console.log("Working Port" + PORT))