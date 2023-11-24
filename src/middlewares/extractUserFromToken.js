const { ApiError } = require("../utils/ApiError");
const User = require("../models/User.model");
const jwt = require("jsonwebtoken");

async function extractUserFromToken(req, res, next) {
  try {
    const payload = jwt.verify(req.token, process.env.JWT_SECRET);

    const user = await User.findById(payload.userId);
    if (!user) return res.status(403).json(new ApiError(["User not found."]));

    req.user = user;

    next();
  } catch (error) {
    console.log(error);
    return res.status(403).json(new ApiError([error.message]));
  }
}

module.exports = {
  extractUserFromToken,
};
