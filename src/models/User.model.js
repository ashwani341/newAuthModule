const mongoose = require("mongoose");
const userSchema = mongoose.Schema(
  {
    firstName: {
      type: String,
    },
    lastName: {
      type: String,
    },
    email: {
      type: String,
      required: [true, "Email is required."],
      unique: true,
    },
    password: {
      type: String,
      required: [true, "Password is required."],
    },
    mobileNo: {
      type: Number,
      default: null,
    },
    roles: {
      type: [mongoose.Schema.Types.ObjectId],
      ref: "Role",
    },
    accessTokens: {
      type: [String],
      default: [],
    },
    refreshToken: {
      type: String,
      default: null,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    isEnabled: {
      type: Boolean,
      default: false,
    },
    lastLogin: {
      type: Date,
      required: true,
    },
    provider: {
      type: String,
      enum: ["local", "google", "mobile"],
      default: "local",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
