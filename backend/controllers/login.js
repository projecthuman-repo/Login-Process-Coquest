/**
 * @module login
 */

/**
 * @function body
 * @const jsonwebtoken
 * @const bcrypt
 * @const User models/user
 * @const loginRouter
 */

const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const loginRouter = require("express").Router();
const User = require("../models/user");
const { getSecret } = require("../utils/gcloud");
/**
 * POST /api/login/
 * Controller method to log in user
 * @memberof module:login~loginRouter
 * @param {Object} request The request
 * @param {Object} response The response
 * @param {string} request.body.username The user's username
 * @param {string} request.body.password The user's password
 * @returns {string} token
 * @returns {string} username
 * @returns {string} firstName
 */
loginRouter.post(
  "/",
  body("username")
    .not()
    .isEmpty()
    .trim()
    .escape()
    .withMessage("Invalid input for username"),
  body("password")
    .not()
    .isEmpty()
    .trim()
    .escape()
    .withMessage("Invalid input for password"),

  async (request, response) => {
    // Obtain list of errors from validation of body
    const errors = validationResult(request).array();
    let list_errors = "";
    for (let i = 0; i < errors.length; i++) {
      list_errors += errors[i].msg + "\n";
    }
    if (list_errors) {
      return response.status(400).json({
        status: "Fail",
        error: list_errors,
      });
    }
    const { username, password } = request.body;
    // Get user via username in request body
    const user = await User.findOne({ username });
    // Check if entered password is same as hashed password
    const passwordCorrect =
      user === null ? false : await bcrypt.compare(password, user.passwordHash);
    // If user doesn't exist or password isn't correct, return error
    if (!(user && passwordCorrect)) {
      return response.status(401).json({
        status: "Fail",
        error: "Invalid username or password",
      });
    }
    // If user is not verified, prevent login
    if (user.isVerified === false) {
      return response.status(401).json({
        status: "Fail",
        error:
          "User does not correspond to a verified account, please check your email and verfy your account if you already registered",
      });
    }

    const userForToken = {
      name: {
        first: user.firstName,
        last: user.lastName,
      },
      username: user.username,
      email: user.email,
    };

    // Update the lastLoginDate field
    user.lastLoginDate = new Date();
    // Save the updated user record
    await user.save();

    // token expires 1hr
    // Sign jwt on login, used for authorization

    const token = jwt.sign(userForToken, await getSecret(process.env.ACCESS_JWT_NAME), {
      expiresIn: "1h",
      subject: user._id.toString(),
    });

    const refreshToken = jwt.sign(userForToken, await getSecret(process.env.REFRESH_JWT_NAME), {
      expiresIn: '7d',
      subject: user._id.toString(),
    });

    // Save the refresh token to the user's record in the database
    user.refreshToken = refreshToken;
    await user.save();

    response.cookie('phc', token);

    response.status(200).json({
      status: "Success",
      token,
      username: user.username,
      firstName: user.firstName,
    });
  }
);

loginRouter.post(
  "/token",
  body("token")
    .not()
    .isEmpty()
    .withMessage("An access token is requried"),
  async (req, res) => {
    const { token } = req.body;
    const accessSecret = await getSecret(process.env.ACCESS_JWT_NAME);
    const refreshSecret = await getSecret(process.env.REFRESH_JWT_NAME);

    const decoded = jwt.decode(token);

    let user = await User.findById(decoded.sub).exec();

    const userForToken = {
      name: {
        first: user.firstName,
        last: user.lastName,
      },
      username: user.username,
      email: user.email,
    };

    jwt.verify(user.refreshToken, refreshSecret, async(err, _) => {
      if (err) {
        return res.sendStatus(403);
      }

      const accessToken = jwt.sign(userForToken, accessSecret, { expiresIn: '1h', subject: user._id.toString(), });
      user.refreshToken = jwt.sign(userForToken, refreshSecret, { expiresIn: '7d', subject: user._id.toString(), });
      await user.save();

      res.json({ accessToken });
    });
  }
);

module.exports = loginRouter;
