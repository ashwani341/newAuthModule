const { transporter } = require("../configs/transporter");
const { EMAIL_VERIFICATION_TOKEN_AGE } = require("../constants/constants");
const { generateToken } = require("./jwt/jwtUtil");

async function sendVerificationEmail(user) {
  try {
    const token = generateToken(
      { userId: user.id },
      { expiresIn: EMAIL_VERIFICATION_TOKEN_AGE }
    );

    const link =
      "<a href=" +
      `${process.env.FRONTEND_URI}/user?token=${token}` +
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

    return await transporter.sendMail(mailOptions);
  } catch (error) {
    console.log(error);
    return;
  }
}

module.exports = {
  sendVerificationEmail,
};
