const express = require("express");
const app = express();
const path = require("path");
const helmet = require("helmet");
const passport = require("passport");
const OAuth2Strategy = require("passport-oauth2").Strategy;

app.use(helmet())
app.use(express.static(path.join(__dirname, "public")));

passport.use(new OAuth2Strategy({
  authorizationURL: "https://github.com/login/oauth/authorize",
  tokenURL: "https://github.com/login/oauth/access_token",
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: `${process.env.URL}/auth/example/callback`
},
(accessToken, refreshToken, profile, cb) => {
  User.findOrCreate({ exampleId: profile.id }, (err, user) => {
    return cb(err, user);
  });
}
));

app.get("/login",
  passport.authenticate("oauth2"));

app.listen(process.env.PORT,
  () => console.log(`Example app listening on port ${process.env.PORT}`));