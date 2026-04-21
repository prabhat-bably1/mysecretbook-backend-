const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { authUser } = require("../middleware/auth");

const router = express.Router();

function makeSecretId(firstName) {
  const cleanName = (firstName || "user").replace(/\s+/g, "").toLowerCase();
  const random = Math.floor(1000 + Math.random() * 9000);
  return `${cleanName}${random}@mysecretbook`;
}

router.post("/signup", async (req, res) => {
  try {
    const {
      firstName,
      middleName,
      email,
      phone,
      password,
      privacy
    } = req.body;

    if (!firstName || !password || (!email && !phone)) {
      return res.status(400).json({
        message: "First name, password and email or phone are required"
      });
    }

    const existingUser = await User.findOne({
      $or: [
        ...(email ? [{ email }] : []),
        ...(phone ? [{ phone }] : [])
      ]
    });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const secretId = makeSecretId(firstName);

    const user = new User({
      firstName,
      middleName: middleName || "",
      email: email || "",
      phone: phone || "",
      password: hashedPassword,
      secretId,
      privacy: privacy || "Private Profile"
    });

    await user.save();

    return res.json({
      message: "Signup successful",
      user: {
        id: user._id,
        firstName: user.firstName,
        middleName: user.middleName,
        email: user.email,
        phone: user.phone,
        secretId: user.secretId,
        privacy: user.privacy,
        blocked: user.blocked
      }
    });
  } catch (error) {
    return res.status(500).json({
      message: "Signup failed",
      error: error.message
    });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body;

    if (!emailOrPhone || !password) {
      return res.status(400).json({ message: "Email/Phone and password are required" });
    }

    const user = await User.findOne({
      $or: [
        { email: emailOrPhone },
        { phone: emailOrPhone },
        { secretId: emailOrPhone }
      ]
    });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    if (user.blocked) {
      return res.status(403).json({
        message: "Your account is blocked",
        blocked: true,
        blockedReason: user.blockedReason || ""
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        middleName: user.middleName,
        email: user.email,
        phone: user.phone,
        secretId: user.secretId,
        privacy: user.privacy,
        blocked: user.blocked,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    return res.status(500).json({
      message: "Login failed",
      error: error.message
    });
  }
});

router.get("/me", authUser, async (req, res) => {
  return res.json({
    user: {
      id: req.user._id,
      firstName: req.user.firstName,
      middleName: req.user.middleName,
      email: req.user.email,
      phone: req.user.phone,
      secretId: req.user.secretId,
      privacy: req.user.privacy,
      blocked: req.user.blocked,
      isAdmin: req.user.isAdmin
    }
  });
});

module.exports = router;
