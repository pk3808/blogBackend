const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');
const User = require('../models/User');
const TempUser = require('../models/TempUser');
const { check, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
require('dotenv').config();

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// Helper function to send emails
const sendEmail = async (options) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });

  await transporter.sendMail(options);
};

// 1. Account Creation Route
router.post(
  '/create-account',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password must be at least 6 characters').isLength({ min: 6 }),
    check('accountType', 'Account type is required').isIn(['admin', 'user']),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, accountType } = req.body;

    try {
      // Check if email exists in any collection
      const existingAdmin = await Admin.findOne({ email });
      const existingUser = await User.findOne({ email });
      const existingTemp = await TempUser.findOne({ email });

      if (existingAdmin || existingUser || existingTemp) {
        return res.status(400).json({ msg: 'Email already in use' });
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Admin account creation
      if (accountType === 'admin') {
        const newAdmin = new Admin({
          email,
          password: hashedPassword,
          isActive: false // Requires manual activation
        });

        await newAdmin.save();
        return res.json({ 
          msg: 'Admin account created. Requires activation by super-admin.' 
        });
      }

      // User account creation (requires OTP)
      if (accountType === 'user') {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60000); // 10 minutes
        
        const tempUser = new TempUser({
          email,
          password: hashedPassword,
          otp,
          expiresAt
        });

        await tempUser.save();
        
        // Send OTP email
        await sendEmail({
          from: process.env.GMAIL_USER,
          to: email,
          subject: 'Your Verification OTP',
          text: `Your OTP code is: ${otp}`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #3498db;">Account Verification</h2>
              <p>Your OTP code is:</p>
              <h1 style="background: #f1f1f1; padding: 15px; 
                         text-align: center; border-radius: 5px;">
                ${otp}
              </h1>
              <p>This code will expire in 10 minutes.</p>
              <p>If you didn't request this, please ignore this email.</p>
            </div>
          `
        });

        return res.json({ 
          success: true,
          msg: 'OTP sent to your email. Verify to complete registration.' 
        });
      }
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// 2. Verify OTP Route
router.post(
  '/verify-otp',
  [
    check('email', 'Valid email required').isEmail(),
    check('otp', 'OTP must be 6 digits').isLength({ min: 6, max: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, otp } = req.body;

    try {
      // Find in temporary collection
      const tempUser = await TempUser.findOne({ email });
      if (!tempUser) {
        return res.status(400).json({ 
          success: false,
          msg: 'Invalid request or OTP expired' 
        });
      }

      // Check expiration
      if (tempUser.expiresAt < new Date()) {
        await TempUser.deleteOne({ _id: tempUser._id });
        return res.status(400).json({ 
          success: false,
          msg: 'OTP expired. Please register again.' 
        });
      }

      // Verify OTP
      if (tempUser.otp !== otp) {
        return res.status(400).json({ 
          success: false,
          msg: 'Invalid OTP' 
        });
      }

      // Create verified user account
      const newUser = new User({
        email: tempUser.email,
        password: tempUser.password
      });

      await newUser.save();
      await TempUser.deleteOne({ _id: tempUser._id });

      res.json({ 
        success: true,
        msg: 'Account verified! You can now log in.' 
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// 3. Resend OTP Route
router.post(
  '/resend-otp',
  [check('email', 'Valid email required').isEmail()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    try {
      // Find existing temp user
      const tempUser = await TempUser.findOne({ email });
      if (!tempUser) {
        return res.status(400).json({ 
          success: false,
          msg: 'No pending registration found for this email' 
        });
      }

      // Generate new OTP and expiration
      const newOtp = Math.floor(100000 + Math.random() * 900000).toString();
      const newExpiresAt = new Date(Date.now() + 10 * 60000); // 10 minutes

      // Update temp user record
      tempUser.otp = newOtp;
      tempUser.expiresAt = newExpiresAt;
      await tempUser.save();

      // Send new OTP email
      await sendEmail({
        from: process.env.GMAIL_USER,
        to: email,
        subject: 'Your New Verification OTP',
        text: `Your new OTP code is: ${newOtp}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #3498db;">New Verification Code</h2>
            <p>Your new OTP code is:</p>
            <h1 style="background: #f1f1f1; padding: 15px; 
                      text-align: center; border-radius: 5px;">
              ${newOtp}
            </h1>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
          </div>
        `
      });

      res.json({ 
        success: true,
        msg: 'New OTP sent to your email' 
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ 
        success: false,
        msg: 'Server error' 
      });
    }
  }
);

// 4. Login Route
router.post(
  '/login',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists(),
    check('accountType', 'Account type is required').isIn(['admin', 'user']),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, accountType } = req.body;

    try {
      // Admin login
      if (accountType === 'admin') {
        const admin = await Admin.findOne({ email });
        if (!admin) {
          return res.status(400).json({ 
            success: false,
            msg: 'Invalid credentials' 
          });
        }

        // Check if admin is activated
        if (!admin.isActive) {
          return res.status(403).json({ 
            success: false,
            msg: 'Account not activated by super-admin' 
          });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
          return res.status(400).json({ 
            success: false,
            msg: 'Invalid credentials' 
          });
        }

        // Generate JWT
        const payload = { admin: { id: admin.id } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        return res.json({ 
          success: true,
          token,
          role: 'admin',
          msg: 'Admin login successful' 
        });
      }

      // User login
      if (accountType === 'user') {
        const user = await User.findOne({ email });
        if (!user) {
          return res.status(400).json({ 
            success: false,
            msg: 'Invalid credentials' 
          });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(400).json({ 
            success: false,
            msg: 'Invalid credentials' 
          });
        }

        // Generate JWT
        const payload = { user: { id: user.id } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        return res.json({ 
          success: true,
          token,
          role: 'user',
          msg: 'User login successful' 
        });
      }
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ 
        success: false,
        msg: 'Server error' 
      });
    }
  }
);

// 5. Forgot Password Route
router.post(
  '/forgot-password',
  [check('email', 'Please include a valid email').isEmail()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    try {
      // Check in both collections
      const admin = await Admin.findOne({ email });
      const user = await User.findOne({ email });
      
      if (!admin && !user) {
        return res.status(400).json({ 
          success: false,
          msg: 'No account found with this email' 
        });
      }

      // Generate reset token
      const payload = {
        id: (admin || user)._id,
        type: admin ? 'admin' : 'user'
      };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

      // Send reset email
      const resetUrl = `http://your-frontend-url/reset-password/${token}`;
      
      await sendEmail({
        from: process.env.GMAIL_USER,
        to: email,
        subject: 'Password Reset Request',
        text: `Click to reset your password: ${resetUrl}`,
        html: `
          <div style="font-family: Arial, sans-serif;">
            <h2 style="color: #3498db;">Password Reset</h2>
            <p>Click the button below to reset your password:</p>
            <a href="${resetUrl}" 
               style="display: inline-block; padding: 10px 20px; 
                      background: #3498db; color: white; 
                      text-decoration: none; border-radius: 5px;">
              Reset Password
            </a>
            <p>This link will expire in 1 hour.</p>
          </div>
        `
      });

      res.json({ 
        success: true,
        msg: 'Password reset email sent' 
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ 
        success: false,
        msg: 'Server error' 
      });
    }
  }
);

// 6. Reset Password Route
router.post(
  '/reset-password/:token',
  [check('password', 'Password must be at least 6 characters').isLength({ min: 6 })],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { password } = req.body;
    const { token } = req.params;

    try {
      // Verify token
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id, type } = decoded;

      // Find in appropriate collection
      let account;
      if (type === 'admin') {
        account = await Admin.findById(id);
      } else if (type === 'user') {
        account = await User.findById(id);
      }

      if (!account) {
        return res.status(400).json({ 
          success: false,
          msg: 'Invalid token' 
        });
      }

      // Update password
      const salt = await bcrypt.genSalt(10);
      account.password = await bcrypt.hash(password, salt);
      await account.save();

      res.json({ 
        success: true,
        msg: 'Password reset successful' 
      });
    } catch (err) {
      console.error(err.message);
      
      if (err.name === 'TokenExpiredError') {
        return res.status(400).json({ 
          success: false,
          msg: 'Reset token expired' 
        });
      }
      
      if (err.name === 'JsonWebTokenError') {
        return res.status(400).json({ 
          success: false,
          msg: 'Invalid token' 
        });
      }
      
      res.status(500).json({ 
        success: false,
        msg: 'Server error' 
      });
    }
  }
);

// 7. Admin Activation Route (for super-admin)
router.post(
  '/activate-admin',
  [
    check('adminId', 'Admin ID is required').notEmpty(),
    check('superAdminPassword', 'Super admin password is required').exists()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { adminId, superAdminPassword } = req.body;

    try {
      // Get super-admin email from .env
      const superAdminEmail = process.env.SUPER_ADMIN_EMAIL;

      console.log("Checking super-admin with email:", superAdminEmail);  // Debugging log

      // Find the super-admin in the database
      const superAdmin = await Admin.findOne({ email: superAdminEmail });

      // Log the result of the query for debugging
      console.log("Found super-admin:", superAdmin);  // Debugging log

      if (!superAdmin) {
        return res.status(400).json({ success: false, msg: "Super admin not found" });
      }

      // Verify super-admin password
      const isMatch = await bcrypt.compare(superAdminPassword, superAdmin.password);
      if (!isMatch) {
        return res.status(400).json({ success: false, msg: "Invalid super-admin credentials" });
      }

      // Find the admin to activate
      const adminToActivate = await Admin.findById(adminId);
      if (!adminToActivate) {
        return res.status(404).json({ success: false, msg: "Admin not found" });
      }

      // Activate the admin
      adminToActivate.isActive = true;
      await adminToActivate.save();

      res.json({ success: true, msg: "Admin activated successfully" });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ success: false, msg: 'Server error' });
    }
  }
);

module.exports = router;