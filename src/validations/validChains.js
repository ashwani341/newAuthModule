const { body } = require("express-validator");

//= validation chain for emails ====================================================================================================
const emailValidationChain = () =>
  body("email").trim().isEmail().withMessage("Invalid email.");

//= validation chain for strong passwords ====================================================================================================
const passwordValidationChain = () =>
  body("password")
    .trim()
    .isStrongPassword()
    .withMessage(
      "Password must be atleast 8 characters long and must contain 1 special character, 1 capital letter and 1 number."
    );

const mobileNoValidationChain = () =>
  body("mobileNo")
    .trim()
    .isMobilePhone("en-IN")
    .withMessage("Not a valid mobile number.");

module.exports = {
  emailValidationChain,
  passwordValidationChain,
  mobileNoValidationChain,
};
