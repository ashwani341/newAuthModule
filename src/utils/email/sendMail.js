const { transporter } = require("../../configs/transporter");
const {
  EMAIL_VERIFICATION_TOKEN_AGE,
  EMAIL_PASSWORD_RESET_TOKEN_AGE,
} = require("../../constants/constants");
const { generateToken } = require("../jwt/jwtUtil");
const PasswordResetToken = require("../../models/PasswordResetToken.model");

async function sendVerificationEmail(user) {
  try {
    const token = generateToken(
      { userId: user.id },
      { expiresIn: EMAIL_VERIFICATION_TOKEN_AGE }
    );

    const link =
      "<a href=" +
      `${process.env.FRONTEND_URI}/users/verify?verificationToken=${token}` +
      "> Click here to Activate </a>";

    const mailOptions = {
      from: '"Shahshikant" <shashikantdhamame07@gmail.com>', // sender address
      to: `${user.email}`, // list of receivers
      subject: "Verify and Activate Your Account", // Subject line
      html: `Dear ${user.email},
              <p>Greetings from C-DAC !!!</p>
              <p>In order to get started. please activate your account by clicking on the link below:</p>
              <p>${link}</p>
              <br/>
              <p>----------------------</p>
              <p>C-DAC, Hyderabad</p>
              <br/>
              <br/>
          `,
    };

    const info = await transporter.sendMail(mailOptions);
    return info;
  } catch (error) {
    console.log(error);
    return;
  }
}

async function sendPasswordVerificationMail(user) {
  try {
    const token = generateToken(
      { userId: user.id },
      { expiresIn: EMAIL_PASSWORD_RESET_TOKEN_AGE }
    );

    //= store token in the db ====================================================================================================
    const passwordResetToken = await PasswordResetToken.findOneAndUpdate(
      { email: user.email },
      { token },
      { new: true }
    );
    if (!passwordResetToken)
      await PasswordResetToken.create({ email: user.email, token });

    const link =
      "<a href=" +
      `${process.env.FRONTEND_URI}/users/password/reset?token=${token}` +
      "> Reset Password </a>";

    const mailOptions = {
      from: '"Shahshikant" <shashikantdhamame07@gmail.com>', // sender address
      to: `${user.email}`, // list of receivers
      subject: "Reset Your Account Password", // Subject line
      html: `Dear ${user.email},
              <p>Greetings from C-DAC !!!</p>
              <p>Your username is <strong>${user.username}</strong>.</p>
              <p>In order to reset your password. please click on the link below:</p>
              <p>${link}</p>
              <br/>
              <p>----------------------</p>
              <p>C-DAC, Hyderabad</p>
              <br/>
              <br/>
          `,
    };

    const info = await transporter.sendMail(mailOptions);
    return info;
  } catch (error) {
    console.log(error);
    return;
  }
}

module.exports = {
  sendVerificationEmail,
  sendPasswordVerificationMail,
};
