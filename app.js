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
const request = require("request");

app.use(helmet())
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
//app.use(bodyParser());
app.use(session({ secret: process.env.SESSION_SECRET }));
app.use(passport.initialize());
app.use(passport.session());

let users = {};

passport.use(new OAuth2Strategy({
  authorizationURL: "https://github.com/login/oauth/authorize",
  tokenURL: "https://github.com/login/oauth/access_token",
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: `${process.env.URL}/login/callback`
},
(accessToken, refreshToken, profile, cb) => {
  request({
      url: `https://api.github.com/user?access_token=${accessToken}`,
      headers: {
        "User-Agent": "request"
      }
    },
    (err, res, body) => {
      if (!err && res.statusCode === 200) {
        console.log("got something")
        const id = JSON.parse(body).id;
        const provider = "github";
        // Normalise the id to make changing / adding providers easier
        const idHash = crypto.createHash("sha256").update(`${provider}/${id}`).digest("hex");
  
        if (!users[idHash]) {
          console.log("No user with hash", idHash)
          users[idHash] = { accessToken, id, provider };
          return cb({ accessToken, id, provider });
        } else {
          console.log("Found user", JSON.stringify(users[idHash]));
          return cb(users[idHash]);
        }
      }
    });
}
));

passport.serializeUser((user, cb) => {
  console.log("serialising", JSON.stringify(user));
  return cb(null, crypto.createHash("sha256").update(`${user.provider}/${user.id}`).digest("hex"));
});

passport.deserializeUser((idHash, cb) => {
  console.log("deserialising", JSON.stringify(idHash));
  if (!users[idHash]) {
    return cb(new Error('hello'));
  } else {
    return cb(null, users[idHash]);
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
    console.log(req.session);
    res.redirect("/");
});

app.listen(process.env.PORT,
  () => console.log(`Example app listening on port ${process.env.PORT}`));