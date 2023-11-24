const { ApiError } = require("../utils/ApiError");

function extractTokenFromAuthHeader(req, res, next) {
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

  req.token = token;
  next();
}

module.exports = {
  extractTokenFromAuthHeader,
};
