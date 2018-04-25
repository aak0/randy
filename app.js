const express = require("express");
const app = express();
const path = require("path");
const helmet = require("helmet");
const passport = require("passport");
const OAuth2Strategy = require("passport-oauth2").Strategy;

app.use(helmet())
app.use(express.static(path.join(__dirname, "public")));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new OAuth2Strategy({
  authorizationURL: "https://github.com/login/oauth/authorize",
  tokenURL: "https://github.com/login/oauth/access_token",
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: `${process.env.URL}login/callback`
},
(accessToken, refreshToken, profile, cb) => {
  // User.findOrCreate({ exampleId: profile.id }, (err, user) => {
  //   return cb(err, user);
  // });
  console.log(JSON.stringify(profile));
  return cb(null, {id: profile.id});
}
));

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

app.get("/login",
  passport.authenticate("oauth2"));

app.get('/login/callback',
  passport.authenticate('oauth2', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect('/');
});

app.listen(process.env.PORT,
  () => console.log(`Example app listening on port ${process.env.PORT}`));