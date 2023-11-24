const mongoose = require("mongoose");

const passwordResetTokenSchema = mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, "Email is required."],
    },
    token: {
      type: String,
      required: [true, "Token is required."],
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("PasswordResetToken", passwordResetTokenSchema);
