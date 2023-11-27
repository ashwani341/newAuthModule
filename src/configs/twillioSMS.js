const accountSid = "ACfb018904a00617c26d3c81934566aece";
const authToken = "054f422df7ba1fe5dca29390b3b4f704";
const client = require("twilio")(accountSid, authToken);

async function sendOTP(to, otp) {
  try {
    const msg = await client.messages.create({
      body: `Your OTP is ${otp} `,
      from: "+13613065613",
      //   to: "+919404252467",
      to: to,
    });

    return msg;
  } catch (error) {
    console.log(error);
    return;
  }
}

module.exports = {
  sendOTP,
};
