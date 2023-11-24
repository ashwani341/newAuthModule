const mongoose = require("mongoose");

const roleSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Role name is required."],
      unique: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Role", roleSchema);
