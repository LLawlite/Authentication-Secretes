require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");

//////////////////////////////// Level 4 security //////////////////////////////////////////

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// var md5 = require('md5'); //level 2 securtity
// const encrypt=require("mongoose-encryption"); //level 1 security

// const bcrypt=require("bcrypt"); //level 3 security
// const saltRounds = 10;

//////////////////////////////// Level 5 security /////////////////////////////////////////////
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    /// level 4 security. The position of code is important
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId:String,
  secret:String
});

userSchema.plugin(passportLocalMongoose); //level 4
userSchema.plugin(findOrCreate);//level 5

//level 1 security

//you have to write this two lines of code before the the bottom  const User=new mongoose.model("User",userSchema);

//this has to be more secure so it is defined in .env file
// const secret="";
// userSchema.plugin(encrypt, { secret: process.env.SECRET ,encryptedFields:["password"]});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy()); //level 4 position of code is important

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
 ///level 5
 passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({ ///level 5
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  // console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/", function (req, res) {
  res.render("home");
});


///level 5
app.get('/auth/google/',
  passport.authenticate('google', { scope: ['profile'] })); ///level 5
app.get("/register", function (req, res) {
  res.render("register");
});
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });


app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/secrets", function (req, res) {
  // if (req.isAuthenticated()) {
  //   res.render("secrets");
  // } else {
  //   res.redirect("/login");
  // }

  User.find({"secret":{$ne:null}},function(err,foundUser){
    if(err)
    {
      console.log(err);
    }else{
      if(foundUser){
        res.render("secrets",{usersWithSecrets:foundUser});
      }
    }
  })
});

app.get("/logout", function (req, res) {
  req.logOut();
  res.redirect("/");
});

app.get("/submit",function(req,res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
app.post("/submit",function(req,res){
  const submittedSecret=req.body.secret;
  console.log(req.user);

  User.findById(req.user.id,function(err,foundUser){
    if(err)
    {
      console.log(err);
    }else{
      if(foundUser)
      {
        foundUser.secret=submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  })
})

app.post("/register", function (req, res) {
  //////////////////////////////////// Level 4 security ///////////////////////////////////

  User.register(
    { username: req.body.username, active: false },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
      }

      var authenticate = User.authenticate();
      authenticate(
        req.body.username,
        req.body.password,
        function (err, result) {
          if (err) {
            console.log(err);
          } else {
            res.redirect("/secrets");
          }

          // Value 'result' is set to false. The user could not be authenticated since the user is not active
        }
      );
    }
  );

  //////////////////////////////////   Level 3 Security /////////////////////////////////

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) { //level 3 security
  //     // Store hash in your password DB.
  //     const newUser=new User({
  //         email: req.body.username,
  //         password:hash //level 3 security
  //     });
  //     newUser.save(function(err){
  //         if(err)
  //         {
  //             console.log(err);
  //         }
  //         else
  //         {
  //             res.render("secrets")
  //         }
  //     });
  // });

  ///////////////////////////////   level 2 security   //////////////////////////////
  // const newUser=new User({
  //     email: req.body.username,
  //     password:md5(req.body.password) //level 2 security
  // });
  // newUser.save(function(err){
  //     if(err)
  //     {
  //         console.log(err);
  //     }
  //     else
  //     {
  //         res.render("secrets")
  //     }
  // });
});

//////////////////////////  level 5 security
app.post('/login',
  passport.authenticate('local', { successRedirect: '/secrets',
                                   failureRedirect: '/login',
                                   failureFlash: true })
);



// app.post("/login", function (req, res) {
//   ////////////////////////////////////////////// level 4 security ////////////////////////////////////

//   const user = new User({
//     username: req.body.username,
//     password: req.body.password,
//   });
//   req.logIn(user, function (err) {
//     if (err) {
//       console.log(err);
//     } else {
//       passport.authenticate("local");
//       res.redirect("/secrets");
//     }
//   });

  // const username=req.body.username;
  // const password=req.body.password;
  // // const password=md5(req.body.password);//level 2
  //  User.findOne({email:username},function(err,foundUser){
  //      if(err)
  //      {
  //          console.log(err);

  //      }
  //      else{
  //          if(foundUser)
  //          {

  //             bcrypt.compare(password, foundUser.password, function(err, result) { //level 3 security
  //                 // result == true
  //                 if(result===true)
  //                 {
  //                     res.render("secrets");
  //                 }
  //             });
  //             //  if(foundUser.password===password){ \\level 2
  //             //      res.render("secrets");
  //             //  }
  //          }
  //      }
  //  });
// });

app.listen(3000, function () {
  console.log("Server started successfully");
});
