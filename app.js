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
const _ = require("lodash");
const Datastore = require("nedb");
const db = new Datastore({ filename: "users.db", autoload: true });
const NedbStore = require("nedb-session-store")(session);

app.use(helmet())
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use(bodyParser());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: false, // Do not store cookies for guests
  cookie: {
    secure: false,
    maxAge: 1000 * 60 * 60 * 72, // 72 hours
  },
  store: new NedbStore({
    filename: "session.db"
  })
}));
app.use(passport.initialize());
app.use(passport.session());

app.set("views", "./views");
app.set("view engine", "pug");

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

    db.findOne({ idHash }, (err, user) => {
      if (!err && user) {
        console.log("Found user", JSON.stringify(user));
        cb(null, user);
      } else {
        db.insert({ idHash, accessToken, id, provider }, 
          (err, user) => {
            if (!err) {
              cb(null, user);
            }
          });
      }
    })
  });
}
));

passport.serializeUser((user, cb) => {
  cb(null, crypto.createHash("sha256").update(`${user.provider}/${user.id}`).digest("hex"));
});

passport.deserializeUser((idHash, cb) => {
  db.findOne({ idHash }, (err, user) => {
    if (!err && user) {
      cb(null, user)
    } else {
      cb(err);
    }
  });
});

app.use(function proceedOrLogin(req, res, next) {
  const freePass = ["/", "/login", "/login/callback"];
  if (req.user || freePass.includes(req.path)) {
    next();
  } else {
    req.session.backTo = req.path;
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

app.get("/", (req, res) => {
  if (req.user) {
    res.render("index-logged-in");
  } else {
    res.render("index");
  }
});

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.get("/starred",
  (req, res) => {
    function anyFive(xs) {
      if (xs.length === 0) return xs;
      if (xs.length === 5) return _.shuffle(xs);
      if (xs.length > 5) {
        return _.sampleSize(xs, 5);
      } else {
        // Pad the array to length 5 while randomising the order
        // [1, 2] -> 3
        const factor = Math.ceil(5 / xs.length);
        // [_, _, _] -> [1, 2, 1, 2, 1, 2]
        const padded = Array(factor).reduce((accum) => {
          accum.concat(xs);
        }, []);
        // [1, 2, 1, 2, 1, 2] -> ~~[2, 2, 1, 2, 1]
        return _.sampleSize(padded, 5);
      }
    }
    github.getStarred(req.user, (starred) => {
      if (anyFive(starred) === 0) {
        res.render("alone");
      } else {
        res.render("starred", { starred: anyFive(starred) });
      }
    });
});

app.get("/starred.json",
  (req, res) => {
    github.getStarred(req.user, (starred) => {
      res.json(starred);
    });
});

app.get("/user",
  (req, res) => {
    github.getUser(req.user, (userData) => {
      res.json(userData);
    });
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
  () => console.log(`Listening on port ${process.env.PORT}`));