const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: "shashikantdhamame07@gmail.com",
    pass: "efzesejdpszqwxkw",
  },
});

module.exports = {
  transporter
}


// let mailOptions = {
//   from: '"Shahshikant" <shashikantdhamame07@gmail.com>', // sender address
//   to: "ashwani341711@gmail.com", // list of receivers
//   subject: "Test", // Subject line
//   html: `<h2>Testing the mail service only!</h2>`, // html body
// };

// // send mail with defined transport object
// transporter.sendMail(mailOptions, (error, info) => {
//   if (error) {
//     return console.log(error);
//   }
//   console.log("Mail sent: %s", info.messageId);
// });
