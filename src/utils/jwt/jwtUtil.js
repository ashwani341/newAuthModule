const jwt = require("jsonwebtoken");
const {
  ACCESS_TOKEN_AGE,
  REFRESH_TOKEN_AGE,
  EMAIL_VERIFICATION_TOKEN_AGE,
  EMAIL_PASSWORD_RESET_TOKEN_AGE,
} = require("../../constants/constants");

const jwtSecret = process.env.JWT_SECRET;

function generateToken(payload, options) {
  return jwt.sign(payload, process.env.JWT_SECRET, options);
}

module.exports = {
  generateToken,
};
