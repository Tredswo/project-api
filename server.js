
// bcrypt encodes code into non human readable format which is difficult to decode 
//jwt is application which provides for bcrypt and decrypt code ; not stored for usind sensitive data as can be decoded easily ; works on base 64 format
//hashing  is used to store sesitive data ; its a algorithm
const express= require("express");
const fs = require("fs");
const path= require("path");
const bcrypt = require("bcrypt");
const { fileURLToPath } = require("url");
const jwt = require("jsonwebtoken");

const app=express();
const PORT=3000;
const secret_key="your_secretkey";

app.use(express.json());

const usersFilePath = path.join(__dirname,"users.json");

const writeJsonFile=(filePath,data)=>{
    fs.writeFileSync(filePath,JSON.stringify(data,null,2));//this means gives 2 spaces with each word and null is when you ente r hence makes the code more readable
};

const  readJsonFile= (filePath)=>{
    const data = fs.readFileSync(filePath,"utf-8");
    return JSON.parse(data);
}    

const authMiddleware=(req,res,next)=>{
    const token = req.headers["auhtorization"];
    if(!token){
        return res.status(401);
    }
    try{
    const decode = jwt.verify(token.split(" ")[1],secret_key);
    console.log(decode);
    req.user = decode;
    next();
    }catch(err){
        res.status(400).json({message:"invalid user"});
    }
}


app.post("/api/auth/register",async (req,res)=>{
    const {username,password}= req.body;
    const users=readJsonFile(usersFilePath);

    if(users.find((user)=>user.username===username)){
        return res.status(400).json({message :"user already exists"});
    }

    const hashedPassword = await bcrypt.hash(password,10);
    users.push({username,password:hashedPassword});
    writeJsonFile(usersFilePath,users);
    res.status(201).json({message:"user registered succesfully"})

});
app.post("/api/auth/login",async(req,res)=>{
    const {username , password } =req.body;
    const users = readJsonFile(usersFilePath);
    const user = users.find((user)=>user.username===username);

    if(!user || !(await bcrypt.compare(password,user.password))){
          return res.status(400).json({message :"Invalid Cred"});
    }
    
    const token= jwt.sign({username}, secret_key,{expiresIn:"1h"});
    res.json({token});
} );



app.get("/api/protected",authMiddleware,(req,res)=>{
    res.json({message:"This is a protected route",user:req.user});
});


app.listen(PORT,()=> console.log(`server running on port ${PORT}`));
