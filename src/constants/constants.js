const ROLES = {
  admin: "Admin",
  user: "User",
};
const ACCESS_TOKEN_AGE = "1d";
const REFRESH_TOKEN_AGE = "30d";
const EMAIL_VERIFICATION_TOKEN_AGE = "1d";
const EMAIL_PASSWORD_RESET_TOKEN_AGE = "1d";
// const COOKIE_AGE = 1000 * 60 * 60 * 24;
// // const COOKIE_AGE = 1000 * 5;
// const SESSION_COOKIE_OPTIONS = {
//   httpOnly: true,
//   sameSite: "none",
//   secure: true,
//   maxAge: COOKIE_AGE,
//   // secure: ture  // sends cookies only on https
// };

module.exports = {
  ROLES,
  ACCESS_TOKEN_AGE,
  REFRESH_TOKEN_AGE,
  EMAIL_VERIFICATION_TOKEN_AGE,
  EMAIL_PASSWORD_RESET_TOKEN_AGE,
  // COOKIE_AGE,
  // SESSION_COOKIE_OPTIONS,
};
