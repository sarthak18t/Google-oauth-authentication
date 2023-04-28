const fs = require("fs");
const https = require("https");
const express = require("express");
const path = require("path");
const helmet = require("helmet");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
const cookieSession = require("cookie-session");


require("dotenv").config();

const app = express();

const config = {
    CLIENT_ID : process.env.CLIENT_ID,
    CLIENT_SECRET : process.env.CLIENT_SECRET,
    COOKIE_KEY_1 : process.env.COOKIE_KEY_1,
    COOKIE_KEY_2 : process.env.COOKIE_KEY_2,
}

const authOptions = {
    callbackURL : "/auth/google/callback",
    clientID : config.CLIENT_ID,
    clientSecret : config.CLIENT_SECRET
}

function verifyCallback(accessToken,refreshToken,profile,done){
    console.log(profile);
    done(null,profile);
}

app.use(helmet());

app.use(cookieSession({
    name : "session",
    maxAge : 24*60*60*100,
    keys : [config.COOKIE_KEY_1 , config.COOKIE_KEY_2]  
}))

app.use(passport.initialize());
app.use(passport.session());

passport.use(new Strategy(authOptions,verifyCallback));

passport.serializeUser((user,done)=>{
    done(null,user.id);
})

passport.deserializeUser((id,done)=>{
    // User.findById(id).then(user=>{
    //     done(null,user)
    // })
    done(null,id);
})


function checkLoggedIn(req,res,next){
    console.log(req.user);
    const loggedIn = req.isAuthenticated() && req.user ; 
    if(!loggedIn){
        return res.status(401).json({
            error : "not logged in",
        })
    }
    next();
}

app.get("/auth/google" ,
    passport.authenticate("google" , {
        scope : ['email'], 
    })
)

app.get("/auth/google/callback" ,
passport.authenticate("google",{
    failureRedirect : "/failure",
    successRedirect : "/",
    session : true
})
,(req,res)=>{
    console.log("call back");
});

app.get("/failure", (req,res)=>{
    res.send("login failed")
})

app.get("/auth/logout" ,(req,res)=>{
    req.logOut(); 
    return res.redirect("/");
})

app.get("/secret",checkLoggedIn,(req,res)=>{
    return res.send("secret")
})

app.get("/",(req,res)=>{
    res.sendFile(path.join(__dirname,"public","index.html"));
})

https.createServer({
    key : fs.readFileSync("key.pem"),
    cert : fs.readFileSync("cert.pem")
},app).listen(3000,()=>{
    console.log("listening");
})