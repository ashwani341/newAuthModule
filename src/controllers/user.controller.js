const { validationResult } = require("express-validator");
const { ApiError } = require("../utils/ApiError");
const { ApiResponse } = require("../utils/ApiResponse");
const getUserRoleId = require("../utils/getUserRoleId");
const { sendVerificationEmail } = require("../utils/sendVerificationEmail");
const User = require("../models/User.model");
const { encryptPassword, verifyPassword } = require("../utils/passwordUtil");
const { generateToken } = require("../utils/jwt/jwtUtil");
const {
  ACCESS_TOKEN_AGE,
  REFRESH_TOKEN_AGE,
} = require("../constants/constants");

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
    const user = await User.create({
      firstName: req.body?.firstName || "",
      lastName: req.body?.lastName || "",
      email: req.body.email,
      password: hashedPassword,
      mobileNo: req.body?.mobileNo || "",
      roles,
      lastLogin,
    });

    //= send verification email ====================================================================================================
    // const emailInfo = await sendVerificationEmail(user); // checked: working
    // if (!emailInfo) {
    //   const deletedUser = await User.findByIdAndDelete(user.id);
    //   throw new Error("Error occured while sending verification email.");
    // }
    // console.log(`Email sent: ${emailInfo.messageId}`);

    //= modifying user to secure sensitive info ====================================================================================================
    const userRes = {
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      mobileNo: user.mobileNo,
      roles: user.roles,
      isVerified: user.isVerified,
      isEnabled: user.isEnabled,
      lastLogin: user.lastLogin,
    };

    return res
      .status(200)
      .json(new ApiResponse(userRes, "User created successfully!"));
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

    //= generate a refresh token ====================================================================================================
    const refreshToken = generateToken(
      { userId: user.id },
      { expiresIn: REFRESH_TOKEN_AGE }
    );

    //= updating accessTokens and refreshToken of the user in the DB ====================================================================================================
    user = await User.findByIdAndUpdate(
      user.id,
      {
        accessTokens: user.accessTokens,
        refreshToken,
        lastLogin: Date.now(),
      },
      {
        new: true,
      }
    );

    const userRes = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      roles: user.roles,
      accessToken: newAccessToken,
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

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
};
