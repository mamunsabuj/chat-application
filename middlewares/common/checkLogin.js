const jwt = require("jsonwebtoken");
const createError = require('http-errors');

// auth guard to protect routes that need authentication
const checkLogin = (req, res, next) => {
  const cookies =
    Object.keys(req.signedCookies).length > 0 ? req.signedCookies : null;

  if (cookies) {
    try {
      token = cookies[process.env.COOKIE_NAME];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;

      // pass user info to response locals
      if (res.locals.html) {
        res.locals.loggedInUser = decoded;
      }
      next();
    } catch (err) {
      if (res.locals.html) {
        res.redirect("/");
      } else {
        res.status(500).json({
          errors: {
            common: {
              msg: "Authentication failure!",
            },
          },
        });
      }
    }
  } else if (res.locals.html) {
    res.redirect("/");
  } else {
    res.status(401).json({
      error: "Authetication failure!",
    });
  }
};

// redirect already logged in user to inbox pabe
const redirectLoggedIn = function (req, res, next) {
  const cookies =
    Object.keys(req.signedCookies).length > 0 ? req.signedCookies : null;

  if (!cookies) {
    next();
  } else {
    res.redirect("/inbox");
  }
};

function requiredRole(role) {
  return function (req, res, next) {
    if (req.user.role && role.includes(req.user.role)) {
      next();
    } else if (res.locals.html) {
      next(createError("You are not authorized to access this page"));
    } else {
      res.status(401).json({
        errors: {
          common: {
            msg: "No Authorized the access this page",
          },
        },
      });
    }
  };
}
module.exports = {
  checkLogin,
  redirectLoggedIn,
  requiredRole,
};
