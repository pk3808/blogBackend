const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');
const { check, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
require('dotenv').config();

const router = express.Router();

// JWT secret key (store this in an environment variable for security)
const JWT_SECRET = process.env.JWT_SECRET;

// Helper function to send the password reset email
const sendResetEmail = async (email, token) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,  // Gmail email (from .env file)
      pass: process.env.GMAIL_PASS,   // Gmail app password (from .env file)
    },
  });

  const resetUrl = `http://localhost:5000/api/auth/reset-password/${token}`;

  const mailOptions = {
    from: process.env.GMAIL_USER,   // Sender's email address (from .env)
    to: email,                      // Recipient's email
    subject: 'Password Reset Request',
    text: `Click the link to reset your password: ${resetUrl}`,
  };

  await transporter.sendMail(mailOptions);  // Send the email
};

// 1. Login Route
router.post(
  '/login',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      const admin = await Admin.findOne({ email });
      if (!admin) {
        return res.status(400).json({ msg: 'Invalid credentials' });
      }

      const isMatch = await bcrypt.compare(password, admin.password);
      if (!isMatch) {
        return res.status(400).json({ msg: 'Invalid credentials' });
      }

      const payload = {
        admin: {
          id: admin.id,
        },
      };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

      res.json({ token });  // Return the token back to the frontend
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);


// 2. Create Admin or User Route
router.post(
  '/create-account',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists().isLength({ min: 6 }),
    check('accountType', 'Account type is required').isIn(['admin', 'user']),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, accountType } = req.body;

    try {
      // Check if account already exists
      const existingUser = await Admin.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ msg: 'Account already exists' });
      }

      // Hash the password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Create a new account
      const newAccount = new Admin({
        email,
        password: hashedPassword,
        accountType,
      });

      if (accountType === 'user') {
        // Generate OTP for email verification
        const otp = Math.floor(100000 + Math.random() * 900000);  // 6-digit OTP
        newAccount.otp = otp;  // Store OTP in database for verification
        newAccount.isVerified = false;  // Initially, the user is not verified

        // Send OTP to user email
        await sendOtpEmail(email, otp);  // Send OTP email
      }

      await newAccount.save();

      res.status(201).json({
        msg: `${accountType.charAt(0).toUpperCase() + accountType.slice(1)} created successfully`,
        account: newAccount,
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// Helper function to send OTP email
const sendOtpEmail = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,  // Gmail email (from .env file)
      pass: process.env.GMAIL_PASS,   // Gmail app password (from .env file)
    },
  });

  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: email,
    subject: 'Email Verification OTP',
    text: `Your OTP for email verification is: ${otp}`,
  };

  await transporter.sendMail(mailOptions);
};

// 3. Forgot Password Route
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
      console.log("Received email for password reset:", email); // Log the email

      const admin = await Admin.findOne({ email });
      if (!admin) {
        console.log("Admin not found with this email:", email); // Log if admin not found
        return res.status(400).json({ msg: 'No admin found with this email' });
      }

      // Generate JWT token for password reset
      const payload = {
        admin: {
          id: admin.id,
        },
      };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

      console.log("Generated reset token:", token); // Log the token for debugging

      // Send reset email
      await sendResetEmail(email, token);  // Send the reset email
      console.log("Reset email sent to:", email);  // Log email sent

      res.json({ msg: 'Password reset email sent' });
    } catch (err) {
      console.error("Error in forgot-password route:", err.message);  // Log detailed error
      res.status(500).send('Server error');
    }
  }
);


// 4. Reset Password Route
router.post(
  '/reset-password/:token',
  [check('password', 'Password is required').exists()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { password } = req.body;
    const { token } = req.params;

    try {
      const decoded = jwt.verify(token, JWT_SECRET);  // Verify the reset token
      const adminId = decoded.admin.id;

      const admin = await Admin.findById(adminId);
      if (!admin) {
        return res.status(400).json({ msg: 'Admin not found' });
      }

      const salt = await bcrypt.genSalt(10);
      admin.password = await bcrypt.hash(password, salt);
      await admin.save();

      res.json({ msg: 'Password reset successful' });
    } catch (err) {
      console.error(err.message);
      if (err.name === 'JsonWebTokenError') {
        return res.status(400).json({ msg: 'Invalid or expired token' });
      }
      res.status(500).send('Server error');
    }
  }
);

// 5. Verify OTP for User
router.post(
  '/verify-otp',
  [check('email', 'Please include a valid email').isEmail(), check('otp', 'OTP is required').exists()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, otp } = req.body;

    try {
      const user = await Admin.findOne({ email });
      if (!user) {
        return res.status(400).json({ msg: 'No user found with this email' });
      }

      if (user.otp !== otp) {
        return res.status(400).json({ msg: 'Invalid OTP' });
      }

      user.isVerified = true;  // Mark the user as verified
      await user.save();

      res.json({ msg: 'Email verified successfully' });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);


module.exports = router;
