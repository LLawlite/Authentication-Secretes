require('dotenv').config();
const express=require("express");
const ejs=require("ejs");
const mongoose=require("mongoose");
const encrypt=require("mongoose-encryption");


const app=express();


app.use(express.static("public"));
app.set('view engine','ejs')
app.use(express.urlencoded({extended:true}));
mongoose.connect('mongodb://localhost:27017/userDB');

const userSchema = new mongoose.Schema({
    email: String,
    password:String
  });

  //you have to write this two lines of code before the the bottom  const User=new mongoose.model("User",userSchema);

//this has to be more secure so it is defined in .env file
// const secret="";
userSchema.plugin(encrypt, { secret: process.env.SECRET ,encryptedFields:["password"]});

  const User=new mongoose.model("User",userSchema);


app.get("/",function(req,res){
    res.render("home");
});
app.get("/register",function(req,res){
    res.render("register");
});
app.get("/login",function(req,res){
    res.render("login");
});

app.post("/register",function(req,res){
    const newUser=new User({
        email: req.body.username,
        password:req.body.password
    })
    newUser.save(function(err){
        if(err)
        {
            console.log(err);
        }
        else
        {
            res.render("secrets")
        }
    });
});

app.post("/login",function(req,res){
    const username=req.body.username;
    const password=req.body.password;
     User.findOne({email:username},function(err,foundUser){
         if(err)
         {
             console.log(err);
             
         }
         else{
             if(foundUser)
             {
                 if(foundUser.password===password){
                     res.render("secrets");
                 }
             }
         }
     });
});


app.listen(3000,function(){
    console.log("Server started successfully");
});
