const GoogleUser = require("../models/GoogleUser");
const User = require("../models/User");
const passport = require("passport");
const getUserRoleId = require("../utils/getUserRoleId");
const { generateAccessToken } = require("../utils/jwt/jwtUtil");
const generateUsername = require("../utils/generateUsername");
const MobileUser = require("../models/MobileUser");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const JwtStrategy = require("passport-jwt").Strategy,
  ExtractJwt = require("passport-jwt").ExtractJwt;

const jwtSecret = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: jwtSecret,
};

const jwtStrategy = new JwtStrategy(opts, async function (jwt_payload, done) {
  try {
    // Find the user associated with the token
    // // // console.log("🚀 ~ file: passportConfig.js:16 ~ jwtStrategy ~ jwt_payload:", jwt_payload)
    let user = null;

    // try to fing in users table
    if (jwt_payload?.userId) user = await User.findById(jwt_payload?.userId);
    if (jwt_payload?.email)
      user = await User.findOne({ email: jwt_payload?.email });

    // try to fing in googleusers table
    if (!user) user = await GoogleUser.findById(jwt_payload?.userId);

    // try to fing in mobileusers table
    if (!user) user = await MobileUser.findById(jwt_payload?.userId);
    console.log("🚀 ~ file: passportConfig.js:36 ~ jwtStrategy ~ user:", user);

    // if not found in any of the tables then error
    if (!user) return done(null, false, { message: "Invalid token: UserID" });

    // Authentication successful
    return done(null, user);
  } catch (err) {
    console.log("jwtStrategy error");
    return done(err, false);
  }
});

// const googleStrategy = new GoogleStrategy(
//   {
//     clientID: GOOGLE_CLIENT_ID,
//     clientSecret: GOOGLE_CLIENT_SECRET,
//     callbackURL: "https://localhost:5000/google/callback",
//   },
//   function (accessToken, refreshToken, profile, done) {
//     // Check if the Google profile is valid
//     console.log(profile);
//     return done(null, profile);
//     // ...
//   }
// );

const googleStrategy = new GoogleStrategy(
  {
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `https://localhost:${process.env.PORT}/api/v1/auth/google/callback`,
  },
  async function (accessToken, refreshToken, profile, cb) {
    // console.log("🚀 ~ file: passportConfig.js:57 ~ profile:", profile);

    try {
      let user = null;

      user = await User.findOne({ email: profile._json.email });

      if (user) return cb("User already exists.");

      user = await GoogleUser.findOne({ email: profile._json.email });

      //= if first time visiting, enter into the database ====================================================================================================
      if (!user) {
        //= assigning default role 'USER' to newUSer ====================================================================================================
        const userRoleId = await getUserRoleId();

        //= generating username ====================================================================================================
        const username = generateUsername(profile._json.email);

        user = await GoogleUser.create({
          sub: profile._json.sub,
          username,
          firstName: profile._json.given_name,
          lastName: profile._json.family_name,
          email: profile._json.email,
          picture: profile._json.picture,
          roles: [userRoleId],
          isVerified: profile._json.email_verified,
          lastLogin: Date.now(),
        });

        //= generate access token ====================================================================================================
        const ownAccessToken = generateAccessToken(user);

        user = await GoogleUser.findOneAndUpdate(
          { email: profile._json.email },
          { accessTokens: [ownAccessToken] },
          { new: true }
        );
        if (!user) return cb("User not found.");
      } else {
        //= generate access token ====================================================================================================
        const ownAccessToken = generateAccessToken(user);
        user.accessTokens.push(ownAccessToken);
        user = await GoogleUser.findByIdAndUpdate(
          user.id,
          {
            accessTokens: user.accessTokens,
          },
          { new: true }
        );

        if (!user) return cb("User not found.");

        user.accessTokens = [ownAccessToken];
      }

      // console.log("🚀 ~ file: passportConfig.js:99 ~ user:", user)
      return cb(null, user);
    } catch (error) {
      console.log(error);
      return cb(error);
    }
  }
);

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, user);
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

module.exports = (passport) => {
  passport.use(jwtStrategy);
  passport.use(googleStrategy);
};
