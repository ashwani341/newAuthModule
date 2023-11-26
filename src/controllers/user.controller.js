const { validationResult } = require("express-validator");
const { ApiError } = require("../utils/ApiError");
const { ApiResponse } = require("../utils/ApiResponse");
const getUserRoleId = require("../utils/getUserRoleId");
const {
  sendVerificationEmail,
  sendPasswordVerificationMail,
} = require("../utils/email/sendMail");
const User = require("../models/User.model");
const { encryptPassword, verifyPassword } = require("../utils/passwordUtil");
const { generateToken } = require("../utils/jwt/jwtUtil");
const {
  ACCESS_TOKEN_AGE,
  REFRESH_TOKEN_AGE,
} = require("../constants/constants");
const PasswordResetTokenModel = require("../models/PasswordResetToken.model");

async function registerUser(req, res) {
  try {
    //#region handling errors from express-validator ####################################################################################################
    const valRes = validationResult(req);
    const errorMessages = valRes.errors.map((element) => element.msg);
    if (errorMessages.length)
      return res.status(400).json(new ApiError(errorMessages));
    //#endregion handling errors from express-validator #################################################################################################

    let userExists = await User.findOne({ email: req.body.email });
    if (userExists)
      return res.status(400).json(new ApiError(["User already exists."]));

    //= assigning default role 'USER' to newUSer ====================================================================================================
    const userRoleId = await getUserRoleId();
    const roles = [userRoleId];
    const lastLogin = Date.now();

    //= hashing the password ====================================================================================================
    const hashedPassword = await encryptPassword(req.body.password);

    //= creating the entry in DB ====================================================================================================
    let user = await User.create({
      firstName: req.body?.firstName || "",
      lastName: req.body?.lastName || "",
      email: req.body.email,
      password: hashedPassword,
      mobileNo: req.body?.mobileNo || "",
      roles,
      lastLogin,
    });

    //= generate a refresh token ====================================================================================================
    const refreshToken = generateToken(
      { userId: user.id },
      { expiresIn: REFRESH_TOKEN_AGE }
    );

    //= updating the refreshToken of the user in the DB ====================================================================================================
    user = await User.findByIdAndUpdate(
      user.id,
      {
        refreshToken,
      },
      {
        new: true,
      }
    );
    console.log(
      "🚀 ~ file: user.controller.js:59 ~ registerUser ~ user:",
      user
    );

    //= send verification email ====================================================================================================
    // const emailInfo = await sendVerificationEmail(user); // checked: working
    // if (!emailInfo) {
    //   const deletedUser = await User.findByIdAndDelete(user.id);
    //   throw new Error("Error occured while sending verification email.");
    // }
    // console.log(`Email verification email sent. ID: ${emailInfo.messageId}`);

    return res
      .status(200)
      .json(new ApiResponse(null, "User created successfully!"));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function verifyUser(req, res) {
  try {
    if (!req.user.isVerified)
      await User.findByIdAndUpdate(
        req.user.id,
        { isVerified: true },
        { new: true }
      );

    return res
      .status(200)
      .json(new ApiResponse(null, "User verified successfully."));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function loginUser(req, res) {
  try {
    //= find the user with the given username ====================================================================================================
    let user = await User.findOne({ email: req.body.email });

    if (!user) return res.status(400).json(new ApiError([`User not found.`]));

    const mylastlogin = user.lastLogin;

    //= Match the stored password and given password ====================================================================================================
    const isPasswordCorrect = await verifyPassword(
      req.body.password,
      user.password
    );
    if (!isPasswordCorrect)
      return res.status(400).json(new ApiError([`Wrong password.`]));

    //= Check if the user email is verified? ====================================================================================================
    if (!user.isVerified)
      return res
        .status(401)
        .json(new ApiError([`Kindly verify your email first.`]));

    //= generate an access token ====================================================================================================
    const newAccessToken = generateToken(
      { userId: user.id },
      { expiresIn: ACCESS_TOKEN_AGE }
    );

    //= Add new access token into user's accessTokens[] ====================================================================================================
    user.accessTokens.push(newAccessToken);

    //= updating accessTokens of the user in the DB ====================================================================================================
    user = await User.findByIdAndUpdate(
      user.id,
      {
        accessTokens: user.accessTokens,
        lastLogin: Date.now(),
      },
      {
        new: true,
      }
    );

    const userRes = {
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      roles: user.roles,
      accessToken: newAccessToken,
      refreshToken: user.refreshToken,
      isVerified: user.isVerified,
      isEnabled: user.isEnabled,
      provider: user.provider,
      lastLogin: mylastlogin,
    };

    return res
      .status(200)
      .json(new ApiResponse(userRes, "User logged in successfully!"));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function logoutUser(req, res) {
  try {
    const user = req.user;
    const accessToken = req.token;

    //= If the token doesn't belongs to the user ====================================================================================================
    if (!user.accessTokens.includes(accessToken))
      return res.status(401).json(new ApiError([`Unauthorized!`]));

    //= Remove the current token from the user.accessTokens ====================================================================================================
    user.accessTokens = user.accessTokens.filter(
      (token) => token !== accessToken
    );

    //= Update the user in the DB ====================================================================================================
    await User.findByIdAndUpdate(
      user.id,
      { accessTokens: user.accessTokens },
      { new: true }
    );

    return res
      .status(200)
      .json(new ApiResponse(null, "User logged out successfully!"));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function sendPasswordResetEmail(req, res) {
  try {
    //#region handling errors from express-validator ####################################################################################################
    const valRes = validationResult(req);
    const errorMessages = valRes.errors.map((element) => element.msg);
    if (errorMessages.length)
      return res.status(400).json(new ApiError(errorMessages));
    //#endregion handling errors from express-validator #################################################################################################

    // == Extract email from req body ==================================================
    const { email } = req.body;

    // == Find the user with the email ==================================================
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json(new ApiError(["User not found."]));

    // == Check if user is verified? ==================================================
    if (!user.isVerified)
      return res
        .status(403)
        .json(new ApiError(["User email is not verified."]));

    // == Send password reset link ==================================================
    // const emailInfo = await sendPasswordVerificationMail(user);
    // if (!emailInfo) {
    //   const deletedTokenDoc = await PasswordResetTokenModel.findOne({
    //     email: user.email,
    //   });
    //   console.log(
    //     "🚀 ~ file: user.controller.js:230 ~ sendPasswordResetEmail ~ deletedTokenDoc:",
    //     deletedTokenDoc
    //   );
    //   throw new Error("Error occured while sending verification email.");
    // }
    // console.log(`Password Reset email sent. ID: ${emailInfo.messageId}`);

    // return res.sendStatus(200);
    return res
      .status(200)
      .json(new ApiResponse(null, "Mail sent successfully!"));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function resetPassword(req, res) {
  try {
    //#region handling errors from express-validator ####################################################################################################
    const valRes = validationResult(req);
    const errorMessages = valRes.errors.map((element) => element.msg);
    if (errorMessages.length)
      return res.status(400).json(new ApiError(errorMessages));
    //#endregion handling errors from express-validator #################################################################################################

    // == Extracting user and token after authentication ==================================================
    const user = req.user;
    const passwordResetToken = req.token;

    // == Check if user is verified? ==================================================
    if (!user.isVerified)
      return res
        .status(403)
        .json(new ApiError(["User email is not verified."]));

    // == Find if the token is there in the DB? ==================================================
    const passwordResetTokenDoc = await PasswordResetTokenModel.findOne({
      email: user.email,
    });
    if (!passwordResetTokenDoc)
      return res
        .status(400)
        .json(new ApiError(["Password reset link not valid. Try again."]));

    // == Extract new password from req body ==================================================
    const { password } = req.body;

    // == Encrypt the password ==================================================
    const hashedPassword = await encryptPassword(password);

    // == Update the user doc in the DB ==================================================
    await User.findByIdAndUpdate(
      user.id,
      { password: hashedPassword, accessTokens: [] }, //Removing all the accessTokens also.
      { new: true }
    );

    // == Delete the token record from the DB ==================================================
    await PasswordResetTokenModel.findOneAndDelete({ email: user.email });

    // return res.sendStatus(200);
    return res
      .status(200)
      .json(new ApiResponse(null, "Password reset successfull."));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

module.exports = {
  registerUser,
  verifyUser,
  loginUser,
  logoutUser,
  sendPasswordResetEmail,
  resetPassword,
};
