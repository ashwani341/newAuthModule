const { ApiError } = require("../utils/ApiError");
const User = require("../models/User.model");
const jwt = require("jsonwebtoken");

async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res
        .status(403)
        .json(new ApiError([`Authorization header not found.`]));
    }

    const [bearer, token] = authHeader.split(" ");

    if (bearer !== "Bearer") {
      return res
        .status(403)
        .json(new ApiError([`Wrong authorization header format.`]));
    }

    if (token === "null" || !token)
      return res.status(403).json(new ApiError([`Token not found.`]));

    const payload = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(payload?.userId);
    if (!user) return res.status(403).json(new ApiError(["User not found."]));

    req.token = token;
    req.user = user;

    next();
  } catch (error) {
    console.log(error);
    return res.status(403).json(new ApiError([error.message]));
  }
}

module.exports = {
  authenticate,
};
