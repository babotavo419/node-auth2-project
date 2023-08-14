const { JWT_SECRET } = require("../secrets"); // use this secret!

const jwt = require('jsonwebtoken');

const Users = require("../users/users-model.js");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Token invalid" });
    }
    req.decodedJwt = decoded;
    next();
  });
}

const only = role_name => (req, res, next) => {
  if (req.decodedJwt && req.decodedJwt.role_name === role_name) {
    next();
  } else {
    res.status(403).json({ message: "This is not for you" });
  }
}

const checkUsernameExists = async (req, res, next) => {
  try {
    const users = await Users.findBy({ username: req.body.username });
    if (users.length) {
      next();
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
}

const validateRoleName = (req, res, next) => {
  if (!req.body.role_name || !req.body.role_name.trim()) {
    req.role_name = "student";
    next();
  } else {
    const trimmedRoleName = req.body.role_name.trim();
    if (trimmedRoleName === "admin") {
      return res.status(422).json({ message: "Role name can not be admin" });
    } else if (trimmedRoleName.length > 32) {
      return res.status(422).json({ message: "Role name can not be longer than 32 chars" });
    } else {
      req.role_name = trimmedRoleName;
      next();
    }
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
