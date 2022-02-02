/////// app.js
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const async = require('async');
const moment = require('moment');
require('dotenv').config();
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const { body } = require("express-validator");
const Schema = mongoose.Schema;
const PORT = process.env.PORT || 5000;

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
        membership: {type: Boolean, default: false},
        admin: {type: Boolean, default: false}
    })
);

// Set up post Schema
const Post = mongoose.model(
    "Post",
    new Schema({
        title: { type: String, required: true },
        message: { type: String, required: true },
        timestamp: {type: Date, default: Date.now},
        author_name: {type: String, required:true},
        author_id: {type: mongoose.Schema.Types.ObjectId, ref: "User", required: true},
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
    async.parallel({
        post: function(callback){
            Post.find()
            .populate('title')
            .populate('message')
            .populate('author_name')
            .populate('timestamp')
            .exec(callback);
        },
    },function(err,results){
        if(err){return next(err);}
        if(results===null){
            const err=new Error('Post not found');
            err.status=404;
            return next(err)
        }
        res.render("./views/index", {user: req.user,post_list:results.post, moment: moment});
    })
});

app.get("/signup", (req, res) => {
    res.render("./views/sign-up-form");
});

app.get("/login", (req, res) => {
    res.render("./views/log-in-form");
});

app.get("/join", (req, res) => {
    res.render("./views/update-membership",{user: req.user});
});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.get("/post", (req, res) => {
    res.render("./views/post-form",{ user: req.user});
});

app.get("/admin", (req, res) => {
    res.render("./views/update-admin",{ user: req.user});
});

app.get("/delete/:id",(req,res,next)=>{
    Post.findById(req.params.id).exec(function(err,post){
        if(err){return next(err)}
        res.render("./views/delete",{post:post,moment:moment})
    })
})

app.post("/login",
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
    })
);

// handle signup form post data
app.post('/signup',(req,res,next)=>{
    body('username').trim().isLength({ min: 1 }).escape().withMessage('Username must be specified.')
    body('password').trim().isLength({ min: 6 }).escape().withMessage('Password must have 6 characters.')
    // if password match with confirmed password
    User.countDocuments({username:req.body.username},function(err,count){
        if(count>0){
            res.render("./views/sign-up-form", {message: 'Username used by someone'});
        }
        else{
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
                        async.parallel({
                            post: function(callback){
                                Post.find()
                                .populate('title')
                                .populate('message')
                                .populate('author_name')
                                .populate('timestamp')
                                .exec(callback);
                            },
                        },function(err,results){
                            if(err){return next(err);}
                            if(results===null){
                                const err=new Error('Post not found');
                                err.status=404;
                                return next(err)
                            }
                            res.render("./views/index", {user: req.user,post_list:results.post,message:'Welcome! Your account has been created', moment: moment});
                        })
                    })
                })
            }else{
                res.render("./views/sign-up-form", {message: 'Password not matched'});
            }
        }
    })
})


//handle post submit form post data
app.post('/post',(req,res,next)=>{
    const post = new Post({
        title: req.body.title,
        message: req.body.message,
        author_name: req.user.username,
        author_id: req.user._id,
    }).save(err=>{
        if(err){return next(err)}
        res.redirect('/')
    })
})

app.post('/join',(req,res,next)=>{
    if (req.body.passcode===process.env.PASSCODE){
        User.findByIdAndUpdate(req.user._id,{membership:true},function(err,result){
            if (err) { return next(err); }
            res.redirect('/')
        })
    }else{
        res.render("./views/update-membership", {message: 'Member Code is wrong',user: req.user});
    }
})

app.post('/admin',(req,res,next)=>{
    if (req.body.admin_code===process.env.ADMINCODE){
        User.findByIdAndUpdate(req.user._id,{admin:true, membership:true},function(err,result){
            if (err) { return next(err); }
            res.redirect('/')
        })
    }else{
        res.render("./views/update-admin", {message: 'Admin Code is wrong',user: req.user});
    }
})

app.post('/delete/:id',(req,res,next)=>{
    Post.findByIdAndRemove(req.params.id,function(err){
        if (err) { return next(err); }
        res.redirect('/')
    })
})

app.listen(PORT, () => console.log(`app listening on port ${ PORT }!`));