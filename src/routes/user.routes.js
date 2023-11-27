const router = require("express").Router();
const { body } = require("express-validator");
const {
  registerUser,
  loginUser,
  logoutUser,
  verifyUser,
  sendPasswordResetEmail,
  resetPassword,
  sendOtp,
  verifyOTPAndRegisterMobileUser,
  updateMobileUser,
} = require("../controllers/user.controller");
const {
  emailValidationChain,
  passwordValidationChain,
  mobileNoValidationChain,
} = require("../validations/validChains");
const { authenticate } = require("../middlewares/authenticate");

const redirectUri = `http://localhost:${process.env.PORT}/api/v1/users/google/callback`;

//#region routes ==================================================
router.post(
  "/register",
  body("firstName").trim().notEmpty().withMessage("First name is required."),
  body("lastName").trim().notEmpty().withMessage("Last name is required."),
  emailValidationChain(),
  passwordValidationChain(),
  mobileNoValidationChain(),
  registerUser
);

router.get("/verify", authenticate, verifyUser);

router.post("/login", loginUser);

router.get("/logout", authenticate, logoutUser);

router.post(
  "/password/reset/sendEmail",
  emailValidationChain(),
  sendPasswordResetEmail
);
router.post(
  "/password/reset",
  passwordValidationChain(),
  authenticate,
  resetPassword
);

router.post("/mobile/sendOTP", mobileNoValidationChain(), sendOtp);

router.post(
  "/mobile/verify",
  mobileNoValidationChain(),
  verifyOTPAndRegisterMobileUser
);

router.put(
  "/mobile/update",
  body("firstName").trim().notEmpty().withMessage("First name is required."),
  body("lastName").trim().notEmpty().withMessage("Last name is required."),
  body("email").trim().optional().isEmail().withMessage("Invalid email."),
  authenticate,
  updateMobileUser
);

router.get("/google", (req, res) => {
  const authUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=email%20profile`;
  return res.redirect(authUrl);
});

router.get("/google/callback", async (req, res) => {
  const code = req.query.code;

  // Exchange the code for an access token
  const tokenUrl = "https://accounts.google.com/o/oauth2/token";
  const tokenParams = {
    code: code,
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  };

  try {
    const tokenResponse = await axios.post(tokenUrl, null, {
      params: tokenParams,
    });
    const accessToken = tokenResponse.data.access_token;

    // Use the access token to get user information
    const userInfoUrl = "https://www.googleapis.com/oauth2/v1/userinfo";
    const userInfoResponse = await axios.get(userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const user = userInfoResponse.data;
    console.log("🚀 ~ file: user.routes.js:100 ~ router.get ~ user:", user);
    res.json(user);
  } catch (error) {
    console.error("Error exchanging code for token:", error.message);
    res.status(500).send("Internal Server Error");
  }
});
//#endregion routes ===============================================

module.exports = router;
