// models/Admin.js
const mongoose = require('mongoose');

const AdminSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  accountType: {
    type: String,
    required: true,
    enum: ['admin', 'user'],  // Only allow 'admin' or 'user' account types
  },
  otp: {
    type: String,  // Store OTP for user verification
  },
  isVerified: {
    type: Boolean,
    default: false,  // Default is not verified
  },
});

module.exports = mongoose.model('Admin', AdminSchema);
