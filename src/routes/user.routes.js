const router = require("express").Router();
const { body } = require("express-validator");
const {
  registerUser,
  loginUser,
  logoutUser,
} = require("../controllers/user.controller");
const {
  emailValidationChain,
  passwordValidationChain,
  mobileNoValidationChain,
} = require("../validations/validChains");
const { authenticate } = require("../middlewares/authenticate");

router.post(
  "/register",
  body("firstName").trim().notEmpty().withMessage("First name is required."),
  body("lastName").trim().notEmpty().withMessage("Last name is required."),
  emailValidationChain(),
  passwordValidationChain(),
  mobileNoValidationChain(),
  registerUser
);

router.post("/login", loginUser);

router.get("/logout", authenticate, logoutUser);

module.exports = router;
