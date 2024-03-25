require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const session = require("express-session"); //
const passport = require("passport");   //
const passportLocalMongoose = require("passport-local-mongoose");   //
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({                                       //
    secret: "Our little secret.",
    resave: false, 
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: [String]
});

userSchema.plugin(passportLocalMongoose);   //
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());    //

passport.serializeUser(function (user, done) {
    done(null, user.id);
});
passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

app.get("/", function(req, res) {
    res.render("home");
})

app.route("/login")
    .get(function(req, res) {
        res.render("login");
    })
    .post(function(req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function(err) {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, function(){
                    res.redirect("/secrets");
                })
            }
        })

        // const username = req.body.username;
        // const password = req.body.password;

        // User.findOne({email: username}, function(err, foundUser) {
        //     if (err){
        //         res.render(err);
        //     } else {
        //         if (foundUser){
        //             bcrypt.compare(password, foundUser.password, function(err, result) {
        //                 if(result === true){
        //                     res.render("secrets");
        //                 }
        //             });
        //         }
        //     }
        // });
    })

app.route("/register")
    .get(function(req, res) {
        res.render("register");
    })
    .post(function(req, res) {
        User.register({username: req.body.username}, req.body.password, function(err, user) {
            if (err) {
                console.log(err);
                res.redirect("/login");
            } else {
                passport.authenticate("local")(req, res, function(){
                    res.redirect("/secrets");
                })
            }
        })

        // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        //     const newUser = new User({
        //         email: req.body.username,
        //         password: hash
        //     });
        //     newUser.save(function(err) {
        //         if (!err){
        //             res.render("secrets");
        //         } else {
        //             res.render(err);
        //         }
        //     });
        // })
    });

app.route("/secrets")
    .get(function(req, res) {
        User.findById(req.user.id, function(err, foundUser) {
            if (err) {
                console.log(err);
            } else {
                if (foundUser) {
                    res.render("secrets", {foundUser: foundUser});
                }
            }
        });
    });
    
app.route("/logout")
    .get(function(req, res) {
        req.logOut();
        res.redirect("/");
    })

app.route("/submit")
    .get(function(req, res) {
        if (req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })
    .post(function(req, res) {
        const newSecret = req.body.secret;
        
        User.findById(req.user.id, function(err, foundUser) {
            if (err) {
                console.log(err);
            } else {
                if (foundUser) {
                    foundUser.secret.push(newSecret);
                    foundUser.save(function() {
                        res.redirect("/secrets");
                    });
                }
            }
        });
    });

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect("/secrets");
    }
);

app.listen(80, function() {
    console.log("server started at port 80");
});