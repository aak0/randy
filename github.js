const request = require("request");

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

module.exports = github;