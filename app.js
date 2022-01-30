/////// app.js
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcryptjs");
require('dotenv').config();
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const { nextTick } = require("process");
const Schema = mongoose.Schema;

const mongoDb = process.env.DB_HOST;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
    "User",
    new Schema({
        username: { type: String, required: true },
        password: { type: String, required: true },
        membership: {type: Boolean, default: false}
    })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
    res.render("./views/index");
});

app.get("/signup", (req, res) => {
    res.render("./views/sign-up-form");
});

app.get("/login", (req, res) => {
    res.render("./views/log-in-form.ejs");
});

// handle signup form post data
app.post('/signup',(req,res,next)=>{
    if(req.body.password===req.body.confirm_password){
        bcrypt.hash(req.body.password,10,(err,hashedPassword)=>{
            if(err){
                return next(err)
            }
            const user = new User({
                username: req.body.username,
                password: hashedPassword,
            }).save(err=>{
                if(err){return next(err)}
                res.redirect('/')
            })
        })
    }
})



app.listen(3000, () => console.log("app listening on port 3000!"));