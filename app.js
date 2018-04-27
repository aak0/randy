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
app.use(bodyParser());
app.use(session({ secret: process.env.SESSION_SECRET }));
app.use(passport.initialize());
app.use(passport.session());

let users = {};

let github = {};
github.getUser = function githubGetUser(accessTokenOrUser, cb) {
  let accessToken;
  if (typeof accessTokenOrUser === "string") {
    accessToken = accessTokenOrUser;
  } else {
    accessToken = accessTokenOrUser.accessToken;
  }
  
  request({
    url: `https://api.github.com/user?access_token=${accessToken}`,
    headers: {
      "User-Agent": "request"
    }
  },(err, res, body) => {
    if (!err && res.statusCode === 200) {
      cb(JSON.parse(body));
    }
  });
}

github.getRepos = function githubGetRepos(user, cb) {
  github.getUser(user, (userData) => {
    request({
      url: `${userData.repos_url}?access_token=${user.accessToken}`,
      headers: {
        "User-Agent": "request"
      }
    },(err, res, body) => {
      if (!err && res.statusCode === 200) {
        cb(JSON.parse(body));
      }
    });
  });
}

github.getStarred = function githubGetStarred(user, cb) {
  github.getUser(user, (userData) => {
    request({
      url: `https://api.github.com/user/starred?access_token=${user.accessToken}`,
      headers: {
        "User-Agent": "request"
      }
    },(err, res, body) => {
      if (!err && res.statusCode === 200) {
        cb(JSON.parse(body));
      }
    });
  });
}

passport.use(new OAuth2Strategy({
  authorizationURL: "https://github.com/login/oauth/authorize",
  tokenURL: "https://github.com/login/oauth/access_token",
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: `${process.env.URL}/login/callback`
},
(accessToken, refreshToken, profile, cb) => {
  github.getUser(accessToken, (userData) => {
    const id = userData.id;
    const provider = "github";
    // Normalise the id to make changing / adding providers easier
    const idHash = crypto.createHash("sha256").update(`${provider}/${id}`).digest("hex");

    if (!users[idHash]) {
      console.log("No user with hash", idHash)
      users[idHash] = { accessToken, id, provider };
      cb(null, { accessToken, id, provider });
    } else {
      console.log("Found user", JSON.stringify(users[idHash]));
      cb(null, users[idHash]);
    }
  });
}
));

passport.serializeUser((user, cb) => {
  cb(null, crypto.createHash("sha256").update(`${user.provider}/${user.id}`).digest("hex"));
});

passport.deserializeUser((idHash, cb) => {
  if (!users[idHash]) {
    cb(new Error());
  } else {
    cb(null, users[idHash]);
  }
});

app.use(function proceedOrLogin(req, res, next) {
  console.log("ROUTE", req.route);
  if (req.user || req.route === "/") {
    return next(req, res);
  } else {
    req.session.backTo = req.route;
    res.redirect("/login");
  }
});

app.get("/login",
  passport.authenticate("oauth2"));

app.get("/repos",
  (req, res) => {
    github.getRepos(req.user, (repos) => {
      res.json(repos);
    });
});

app.get("/starred",
  (req, res) => {
    if (req.user) {
      github.getStarred(req.user, (starred) => {
        console.log("Got some stars");
        res.json(starred);
      });
    } else {
      req.session.backTo = "/starred";
      res.redirect("/login");
    }
});

app.get("/user",
  (req, res) => {
    if (req.user) {
      github.getUser(req.user, (userData) => {
        res.json(userData);
      });
    } else {
      req.session.backTo = "/user";
      res.redirect("/login");
    }
});

app.get("/login/callback",
  passport.authenticate("oauth2", { failureRedirect: "/login" }),
  // Successful authentication, redirect back.
  (req, res) => {
    res.redirect(req.session.backTo || "/");
    req.session.backTo = "";
  }
);

app.listen(process.env.PORT,
  () => console.log(`Example app listening on port ${process.env.PORT}`));