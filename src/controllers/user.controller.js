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
const { generateOTP } = require("../utils/generateOTP");
const { sendOTP } = require("../configs/twillioSMS");
const OTPModel = require("../models/OTP.model");
const { default: axios } = require("axios");
const jwt = require("jsonwebtoken");

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
      return res.status(400).json(new ApiError(["Email already registered."]));

    const mobileUserExists = await User.findOne({
      mobileNo: req.body?.mobileNo,
    });
    if (mobileUserExists)
      return res
        .status(400)
        .json(new ApiError(["Mobile no. already registered."]));

    //= assigning default role 'USER' to newUSer ====================================================================================================
    const userRoleId = await getUserRoleId();
    console.log(
      "🚀 ~ file: user.controller.js:33 ~ registerUser ~ userRoleId:",
      userRoleId
    );
    if (!userRoleId) throw new Error("Role ID not found.");
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

    //= if user is loging in first time the there will be no refresh token ==================================================
    if (!user?.refreshToken) {
      user.refreshToken = generateToken(
        { userId: user.id },
        { expiresIn: REFRESH_TOKEN_AGE }
      );
    }

    //= updating accessTokens and refreshToken of the user in the DB ====================================================================================================
    user = await User.findByIdAndUpdate(
      user.id,
      {
        accessTokens: user.accessTokens,
        refreshToken: user.refreshToken,
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

    // == Check if user is "local" not "mobile" or "google"  ==================================================
    if (user.provider !== "local")
      return res.status(403).json(new ApiError(["Forbidden!"]));

    // == Check if user is verified? ==================================================
    if (!user.isVerified)
      return res
        .status(403)
        .json(new ApiError(["User email is not verified."]));

    // == Send password reset link ==================================================
    const emailInfo = await sendPasswordVerificationMail(user);
    if (!emailInfo) {
      const deletedTokenDoc = await PasswordResetTokenModel.findOne({
        email: user.email,
      });
      console.log(
        "🚀 ~ file: user.controller.js:230 ~ sendPasswordResetEmail ~ deletedTokenDoc:",
        deletedTokenDoc
      );
      throw new Error("Error occured while sending verification email.");
    }
    console.log(`Password Reset email sent. ID: ${emailInfo.messageId}`);

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

async function sendOtp(req, res) {
  try {
    //#region handling errors from express-validator ####################################################################################################
    const valRes = validationResult(req);
    const errorMessages = valRes.errors.map((element) => element.msg);
    if (errorMessages.length)
      return res.status(400).json(new ApiError(errorMessages));
    //#endregion handling errors from express-validator #################################################################################################

    // == Generate an OTP ==================================================
    const OTP = generateOTP();

    // == Update the OTP in the DB ==================================================
    let otpDoc = await OTPModel.findOneAndUpdate(
      { mobileNo: req.body.mobileNo },
      { otp: OTP },
      { new: true }
    );

    // == if no previous record then create the new one  ==================================================
    if (!otpDoc)
      otpDoc = await OTPModel.create({
        mobileNo: req.body.mobileNo,
        otp: OTP,
      });
    console.log(
      "🚀 ~ file: user.controller.js:335 ~ sendOtp ~ otpDoc:",
      otpDoc
    );

    // == Send OTP ==================================================
    const msgInfo = await sendOTP(req.body.mobileNo, OTP);
    if (!msgInfo) throw new Error("Something went worng while sending OTP.");
    console.log(
      "🚀 ~ file: user.controller.js:341 ~ sendOtp ~ msgInfo:",
      msgInfo
    );

    // return res.sendStatus(200);
    return res
      .status(200)
      .json(new ApiResponse(null, "OTP sent successfully!"));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function verifyOTPAndRegisterMobileUser(req, res) {
  try {
    //#region handling errors from express-validator ####################################################################################################
    const valRes = validationResult(req);
    const errorMessages = valRes.errors.map((element) => element.msg);
    if (errorMessages.length)
      return res.status(400).json(new ApiError(errorMessages));
    //#endregion handling errors from express-validator #################################################################################################
    // return res.sendStatus(200);

    // == Check if the otp is present in the DB? ==================================================
    const otpDoc = await OTPModel.findOne({ mobileNo: req.body.mobileNo });
    if (!otpDoc)
      return res
        .status(500)
        .json(new ApiError(["OTP not found for this mobile no."]));

    // == Check if the otp comming from the req is equal to the stored one? ==================================================
    if (parseInt(req.body.otp) !== otpDoc.otp)
      return res.status(500).json(new ApiError(["OTP verification failed."]));

    // == If everythig is good delete the otp entry ==================================================
    await OTPModel.findOneAndDelete({ mobileNo: req.body.mobileNo });

    // == Check if the mobile no. already in the DB ==================================================
    let user = await User.findOne({ mobileNo: req.body.mobileNo });
    if (user && user.provider !== "mobile")
      return res
        .status(400)
        .json(new ApiError(["Mobile no. already registered."]));

    if (!user) {
      //= Create a default role 'USER' for new user ====================================================================================================
      const userRoleId = await getUserRoleId();
      if (!userRoleId) throw new Error("Role ID not found.");
      const roles = [userRoleId];

      //= Store the new user in DB ====================================================================================================
      user = await User.create({
        mobileNo: req.body.mobileNo,
        roles,
        isVerified: true,
        lastLogin: Date.now(),
        provider: "mobile",
      });
    }

    //= generate an access token ====================================================================================================
    const newAccessToken = generateToken(
      { userId: user.id },
      { expiresIn: ACCESS_TOKEN_AGE }
    );

    //= Add new access token into user's accessTokens[] ====================================================================================================
    user.accessTokens.push(newAccessToken);

    //= if user is loging in first time the there will be no refresh token ==================================================
    if (!user?.refreshToken) {
      user.refreshToken = generateToken(
        { userId: user.id },
        { expiresIn: REFRESH_TOKEN_AGE }
      );
    }

    //= updating accessTokens and refreshToken of the user in the DB ====================================================================================================
    user = await User.findByIdAndUpdate(
      user.id,
      {
        accessTokens: user.accessTokens,
        refreshToken: user.refreshToken,
        lastLogin: Date.now(),
      },
      {
        new: true,
      }
    );

    const userRes = {
      firstName: user?.firstName || "",
      lastName: user?.lastName || "",
      email: user?.email || "",
      roles: user.roles,
      accessToken: newAccessToken,
      refreshToken: user.refreshToken,
      isVerified: user.isVerified,
      isEnabled: user.isEnabled,
      provider: user.provider,
      lastLogin: user.lastLogin,
    };

    return res
      .status(200)
      .json(new ApiResponse(userRes, "OTP verification succussfull."));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function updateMobileUser(req, res) {
  try {
    //#region handling errors from express-validator ####################################################################################################
    const valRes = validationResult(req);
    const errorMessages = valRes.errors.map((element) => element.msg);
    if (errorMessages.length)
      return res.status(400).json(new ApiError(errorMessages));
    //#endregion handling errors from express-validator #################################################################################################

    // == Extract authenticated user ==================================================
    let user = req.user;

    // == Check if the user is mobile user? ==================================================
    if (user.provider !== "mobile")
      return res.status(401).json(new ApiError(["Unauthorized!"]));

    // == Update firstName and lastName of the mobile user ==================================================
    user = await User.findByIdAndUpdate(
      { _id: user.id },
      {
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body?.email,
      },
      { new: true }
    );
    if (!user) return res.status(400).json(new ApiError(["User not found."]));

    // return res.sendStatus(200);
    return res
      .status(200)
      .json(new ApiResponse(null, "User updated successfully."));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function handleGoogleCallback(req, res) {
  try {
    //#region handling errors from express-validator ####################################################################################################
    const valRes = validationResult(req);
    const errorMessages = valRes.errors.map((element) => element.msg);
    if (errorMessages.length)
      return res.status(400).json(new ApiError(errorMessages));
    //#endregion handling errors from express-validator #################################################################################################

    //#region fetch user from google api ####################################################################################################
    const code = req.query.code;

    // Exchange the code for an access token
    const redirectUri = `http://localhost:${process.env.PORT}/api/v1/users/google/callback`;
    const tokenParams = {
      code: code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    };

    const tokenResponse = await axios.post(
      "https://accounts.google.com/o/oauth2/token",
      null,
      {
        params: tokenParams,
      }
    );
    const accessToken = tokenResponse.data.access_token;

    // Use the access token to get user information
    const userInfoResponse = await axios.get(
      "https://www.googleapis.com/oauth2/v1/userinfo",
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    );

    const googleUser = userInfoResponse.data;
    //#endregion fetch user from google api #################################################################################################

    //= check if the user already exists in DB? ====================================================================================================
    let user = await User.findOne({ email: googleUser.email });

    if (user && user.provider !== "google")
      return res.status(403).json(new ApiError(["Email already registered."]));

    //= If user is not there in the DB the add ==================================================
    if (!user) {
      //= assigning default role 'USER' to newUSer ====================================================================================================
      const userRoleId = await getUserRoleId();
      console.log(
        "🚀 ~ file: user.controller.js:33 ~ registerUser ~ userRoleId:",
        userRoleId
      );
      if (!userRoleId) throw new Error("Role ID not found.");
      const roles = [userRoleId];
      const lastLogin = Date.now();

      user = await User.create({
        firstName: googleUser?.given_name || "",
        lastName: googleUser?.family_name || "",
        email: googleUser?.email || "",
        roles,
        isVerified: true,
        lastLogin,
        provider: "google",
      });
    }

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

    //= if user is loging in first time the there will be no refresh token ==================================================
    if (!user?.refreshToken) {
      user.refreshToken = generateToken(
        { userId: user.id },
        { expiresIn: REFRESH_TOKEN_AGE }
      );
    }

    //= updating accessTokens and refreshToken of the user in the DB ====================================================================================================
    user = await User.findByIdAndUpdate(
      user.id,
      {
        accessTokens: user.accessTokens,
        refreshToken: user.refreshToken,
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
      lastLogin: user.lastLogin,
    };

    return res
      .status(200)
      .json(new ApiResponse(userRes, "User authorization successfull."));
  } catch (error) {
    console.error(error);
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function handleRefreshToken(req, res) {
  //= Extract tokens from req headers ==================================================
  const accessToken = req.headers?.accesstoken;
  const refreshToken = req.headers?.refreshtoken;

  //= If any one of them is not found? :send error ==================================================
  if (!accessToken || !refreshToken)
    return res.status(400).json(new ApiError([`Headers not found.`]));

  try {
    //= Verify refresh token ==================================================
    const payload = jwt.verify(refreshToken, process.env.JWT_SECRET);

    //= Find the user of the token ==================================================
    let user = await User.findById(payload?.userId);

    //= If payload userId is altered and user not found with the right refersh token & user doesn't have the access token comming in req? :send error ==================================================
    if (!user || !user.accessTokens.includes(accessToken))
      return res.status(403).json(new ApiError([`Forbidden!`]));

    //= Remove the expired access token  ==================================================
    const filteredAccessTokens = user.accessTokens.filter(
      (token) => token !== accessToken
    );

    //= Generate a new access token ====================================================================================================
    const newAccessToken = generateToken(
      { userId: user.id },
      { expiresIn: ACCESS_TOKEN_AGE }
    );

    //= Add new access token into the filtered tokens ====================================================================================================
    filteredAccessTokens.push(newAccessToken);

    //#region If refresh token is about to expire ====================================================================================================
    // Expiration time in seconds since Unix epoch
    const expirationTimeInSeconds = payload.exp;

    // Current time in seconds since Unix epoch
    const currentTimeInSeconds = Math.floor(Date.now() / 1000);

    // Set a threshold (e.g., 5 minutes) for considering the token as "about to expire"
    const thresholdInSeconds = 5 * 60;

    // Check if the token is about to expire
    if (expirationTimeInSeconds - currentTimeInSeconds < thresholdInSeconds) {
      console.log("The JWT token is about to expire soon.");

      user.refreshToken = generateToken(
        { userId: user.id },
        { expiresIn: REFRESH_TOKEN_AGE }
      );
    }
    //#endregion If refresh token is about to expire =================================================================================================

    //= Updating accessTokens of the user in the DB ====================================================================================================
    user = await User.findByIdAndUpdate(
      user.id,
      {
        accessTokens: filteredAccessTokens,
        refreshToken: user.refreshToken,
      },
      {
        new: true,
      }
    );

    return res
      .status(200)
      .json(
        new ApiResponse(
          { newAccessToken, refreshToken: user.refreshToken },
          "Token refresh successfull."
        )
      );
  } catch (error) {
    // console.log("🚀 ~ file: user.controller.js:673 ~ handleRefreshToken ~ error:", JSON.stringify(error))
    if (error.name === "TokenExpiredError") {
      try {
        const user = await User.findOne({ refreshToken });

        if (!user) return res.status(403).json(new ApiError([`Forbidden!`]));

        //= Just remove all the accessTokens and refreshToken ==================================================
        await User.findByIdAndUpdate(
          user.id,
          {
            accessTokens: [],
            refreshToken: null,
          },
          {
            new: true,
          }
        );

        return res
          .status(400)
          .json(new ApiResponse(null, "Kindly login again."));
      } catch (err) {
        error = err;
      }
    }

    console.log(
      "🚀 ~ file: user.controller.js:693 ~ handleRefreshToken ~ error:",
      error
    );
    return res.status(500).json(new ApiError([error.message]));
  }
}

async function sendUserDetails(req, res) {
  try {
    //= Find the user in DB ==================================================
    const user = await User.findById(req.user.id);

    const userRes = {
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      roles: user.roles,
      isVerified: user.isVerified,
      isEnabled: user.isEnabled,
      provider: user.provider,
      lastLogin: mylastlogin,
    };

    return res
      .status(200)
      .json(new ApiResponse(userRes, "User created successfully!"));
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
  sendOtp,
  verifyOTPAndRegisterMobileUser,
  updateMobileUser,
  handleGoogleCallback,
  handleRefreshToken,
  sendUserDetails,
};
