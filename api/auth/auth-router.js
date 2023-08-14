const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs');

const Users = require("../users/users-model.js");  // Importing the user model for database access

router.post("/register", validateRoleName, async (req, res, next) => {
  const { username, password } = req.body;
  const role_name = req.role_name;

  try {
    const hash = bcrypt.hashSync(password, 10);
    const user = await Users.add({ username, password: hash, role_name });
    res.status(201).json(user);
  } catch (err) {
    next(err);
  }
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,  // standard claim = sub
    username: user.username,
    role_name: user.role_name
  };
  const options = {
    expiresIn: '1d',  // token will expire in 1 day
  };
  return jwt.sign(payload, JWT_SECRET, options);
}

router.post("/login", checkUsernameExists, async (req, res, next) => {
  const { password } = req.body;

  try {
    const [user] = await Users.findBy({ username: req.body.username });
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = buildToken(user);
      res.status(200).json({
        message: `${user.username} is back!`,
        token
      });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
});
  

module.exports = router;
