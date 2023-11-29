const client = require("twilio")(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
); //Shashi bro's account

async function sendOTP(to, otp) {
  try {
    const msg = await client.messages.create({
      body: `Your OTP is ${otp} `,
      // from: "+14694164781",
      from: "+14242553721",
      //   to: "+919404252467",
      to: `+91${to}`,
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
