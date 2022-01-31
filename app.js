/////// app.js
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
require('dotenv').config();
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const mongoDb = process.env.DB_HOST;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

// Set up user Schema
const User = mongoose.model(
    "User",
    new Schema({
        username: { type: String, required: true },
        password: { type: String, required: true },
        membership: {type: Boolean, default: false}
    })
);

// Set up post Schema
const Post = mongoose.model(
    "Post",
    new Schema({
        title: { type: String, required: true },
        message: { type: String, required: true },
        timestamp: {type: Date, default: Date.now},
        author: {type: mongoose.Schema.Types.ObjectId, ref: "User", required: true}
    })
);


// LocalStrategy take function as argument
passport.use(
    new LocalStrategy((username, password, done) => {
      User.findOne({ username: username }, (err, user) => {
        if (err) { 
          return done(err);
        }
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        bcrypt.compare(password, user.password, (err, res) => {
            if (res) {
              // passwords match! log user in
              return done(null, user)
            } else {
              // passwords do not match!
              return done(null, false, { message: "Incorrect password" })
            }
        })
        return done(null, user);
      });
    })
);

// get ID from user information
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

// get id by using user information
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

const app = express();
app.set("views", __dirname);
app.set("view engine", "jade");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));


app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
});


app.get("/", (req, res) => {
    res.render("./views/index", { user: req.user });
});

app.get("/signup", (req, res) => {
    res.render("./views/sign-up-form");
});

app.get("/login", (req, res) => {
    res.render("./views/log-in-form");
});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.get("/post", (req, res) => {
    res.render("./views/post-form");
});

app.post("/login",
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login'
    })
);

// handle signup form post data
app.post('/signup',(req,res,next)=>{
    // if password match with confirmed password
    if(req.body.password===req.body.confirm_password){
        // ecrypt the user password with bcrypt
        bcrypt.hash(req.body.password,10,(err,hashedPassword)=>{
            if(err){
                return next(err)
            }
            // save username and hashed password into DB
            const user = new User({
                username: req.body.username,
                password: hashedPassword,
            }).save(err=>{
                if(err){return next(err)}
                // return to home page after success
                res.redirect('/')
            })
        })
    }
})


//handle post submit form post data
app.post('/post',(req,res,next)=>{
    console.log(req.user)
    const post = new Post({
        title: req.body.title,
        message: req.body.message,
        author: req.user._id,
    }).save(err=>{
        if(err){return next(err)}
        res.redirect('/')
    })
})


app.listen(3000, () => console.log("app listening on port 3000!"));