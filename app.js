const express = require("express");
const app = express();
const path = require("path");
const helmet = require("helmet");
const passport = require("passport");
const OAuth2Strategy = require("passport-oauth2").Strategy;
const crypto = require("crypto");
const bodyParser = require("body-parser");
const session = require("express-session");
const cookieParser = require("cookie-parser");

app.use(helmet())
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use(bodyParser());
app.use(session({ secret: process.env.SESSION_SECRET }));
app.use(passport.initialize());
app.use(passport.session());

let users = new Map();

passport.use(new OAuth2Strategy({
  authorizationURL: "https://github.com/login/oauth/authorize",
  tokenURL: "https://github.com/login/oauth/access_token",
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: `${process.env.URL}login/callback`
},
(accessToken, refreshToken, profile, cb) => {
  const hash = crypto.createHash("sha256").update(accessToken).digest("base64");
  console.log(hash);
  if (typeof users[hash] !== "undefined") {
    console.log("stored token", users[hash]);
    return cb(null, users[hash]);
  } else {
    users[hash] = accessToken;
    return cb(null, accessToken);
  }
}
));

passport.serializeUser((accessToken, cb) => {
  return cb(null, crypto.createHash("sha256").update(accessToken).digest("base64"));
});

passport.deserializeUser((hash, cb) => {
  if (typeof users[hash] !== "undefined") {
    return cb(null, users[hash]);
  } else {
    return cb(new Error());
  }
});

app.get("/login",
  passport.authenticate("oauth2"));

app.get("/repos",
  (req, res) => {
    res.json(req.user);
});

app.get("/login/callback",
  passport.authenticate("oauth2", { failureRedirect: "/login" }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect("/");
});

app.listen(process.env.PORT,
  () => console.log(`Example app listening on port ${process.env.PORT}`));