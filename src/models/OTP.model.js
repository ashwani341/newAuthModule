const mongoose = require("mongoose");
const otpSchema = mongoose.Schema(
  {
    mobile: {
      type: String,
      required: [true, "Mopbile no. is required."],
      unique: true,
    },
    otp: {
      type: Number,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("OTP", otpSchema);
