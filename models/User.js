const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    default: ""
  },
  middleName: {
    type: String,
    default: ""
  },
  email: {
    type: String,
    default: "",
    unique: true,
    sparse: true
  },
  phone: {
    type: String,
    default: "",
    unique: true,
    sparse: true
  },
  password: {
    type: String,
    required: true
  },
  secretId: {
    type: String,
    required: true,
    unique: true
  },
  privacy: {
    type: String,
    default: "Private Profile"
  },
  blocked: {
    type: Boolean,
    default: false
  },
  blockedReason: {
    type: String,
    default: ""
  },
  isAdmin: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("User", userSchema);
