const accountSid = "ACfb018904a00617c26d3c81934566aece";
const authToken = "054f422df7ba1fe5dca29390b3b4f704";
const client = require("twilio")(accountSid, authToken);

function sendOTP(to, otp) {
  client.messages
    .create({
      body: `Your OTP is ${otp} `,
      from: "+13613065613",
      //   to: "+919404252467",
      to: to,
    })
    .then((message) => console.log(message.sid))
    .catch((err) => console.log(err));
}

module.exports = {
  sendOTP,
};
