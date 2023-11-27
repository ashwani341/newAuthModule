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

//#endregion routes ===============================================

module.exports = router;
