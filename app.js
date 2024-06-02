const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
require("dotenv").config();

const mongoDb = process.env.MONGO_URL;
mongoose.connect(mongoDb);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

const app = express();
console.log(path.join(__dirname, "views"));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// local store strategies //

// authentication strategy
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "no username found" });
      }
      // compare hashed pw
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passowrd does not match
        return done(null, false, message("incorrect password"));
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// session and serialization - callback to information we want to store in the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// retrieve a session. Extract the serialized data and check against the db
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// end points //

app.get("/", (req, res) => res.render("index", { user: req.user }));

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
  bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
    try {
      const user = new User({
        username: req.body.username,
        password: hashedPassword,
      });
      const result = await user.save();
      res.locals.currentUser = user;
      res.redirect("/");
    } catch (err) {
      return next(err);
    }
  });
});

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/oops",
  })
);

app.listen(3000, () => console.log("app listening on port 3000!"));
