const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");
const morgan = require("morgan");

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true, limit: "15mb" }));
app.use(morgan("dev"));

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";
const MONGODB_URI = process.env.MONGODB_URI;

// ======================
// MongoDB Connect
// ======================
mongoose
  .connect(MONGODB_URI)
  .then(async () => {
    console.log("MongoDB Connected ✅");
    await createDefaultAdmin();
  })
  .catch((err) => {
    console.error("MongoDB Connection Error ❌", err.message);
  });

// ======================
// Schemas
// ======================
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 50,
    },
    username: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      lowercase: true,
      minlength: 3,
      maxlength: 30,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      lowercase: true,
    },
    phone: {
      type: String,
      default: "",
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    secretId: {
      type: String,
      unique: true,
      sparse: true,
      default: "",
    },
    bio: {
      type: String,
      default: "",
      maxlength: 300,
    },
    profileImage: {
      type: String,
      default: "",
    },
    privacy: {
      type: String,
      default: "Private Profile",
    },
    blocked: {
      type: Boolean,
      default: false,
    },
    blockedReason: {
      type: String,
      default: "",
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

const commentSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    name: {
      type: String,
      required: true,
    },
    text: {
      type: String,
      required: true,
      trim: true,
      maxlength: 500,
    },
  },
  { timestamps: true }
);

const postSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    authorName: {
      type: String,
      required: true,
    },
    secretId: {
      type: String,
      default: "",
    },
    email: {
      type: String,
      default: "",
    },
    phone: {
      type: String,
      default: "",
    },
    text: {
      type: String,
      default: "",
      maxlength: 5000,
    },
    image: {
      type: String,
      default: "",
    },
    likes: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    comments: [commentSchema],
    shares: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", postSchema);

// ======================
// Helpers
// ======================
function makeSecretId(username) {
  const clean = String(username || "user")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "")
    .replace(/[^a-z0-9_]/g, "");
  return `${clean}@mysecretbook`;
}

async function createDefaultAdmin() {
  try {
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;

    if (!adminEmail || !adminPassword) {
      console.log("Admin env not found");
      return;
    }

    const existingAdmin = await User.findOne({
      email: adminEmail.toLowerCase(),
    });

    if (existingAdmin) {
      if (!existingAdmin.isAdmin) {
        existingAdmin.isAdmin = true;
        existingAdmin.blocked = false;
        existingAdmin.blockedReason = "";
        if (!existingAdmin.secretId) {
          existingAdmin.secretId = "admin@mysecretbook";
        }
        await existingAdmin.save();
      }
      console.log("Admin already exists");
      return;
    }

    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    const adminUser = await User.create({
      name: "Admin",
      username: "adminmsb",
      email: adminEmail.toLowerCase(),
      phone: "",
      password: hashedPassword,
      secretId: "admin@mysecretbook",
      bio: "Default admin",
      profileImage: "",
      privacy: "Private Profile",
      blocked: false,
      blockedReason: "",
      isAdmin: true,
    });

    console.log("Default admin created:", adminUser.email);
  } catch (error) {
    console.log("Default admin create error:", error.message);
  }
}

// ======================
// Auth Middleware
// ======================
const auth = async (req, res, next) => {
  try {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "No token provided",
      });
    }

    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid token user",
      });
    }

    if (user.blocked) {
      return res.status(403).json({
        success: false,
        message: "Your account is blocked",
        blocked: true,
        blockedReason: user.blockedReason || "",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized",
      error: error.message,
    });
  }
};

const adminAuth = async (req, res, next) => {
  try {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "No token provided",
      });
    }

    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid token user",
      });
    }

    if (!user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: "Admin access denied",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized admin",
      error: error.message,
    });
  }
};

// ======================
// Root Route
// ======================
app.get("/", (req, res) => {
  res.send("My Secret Book Backend Running 🚀");
});

// ======================
// Auth Routes
// ======================

// Signup
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, username, email, phone, password, privacy } = req.body;

    if (!name || !username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, username, email and password are required",
      });
    }

    const emailLower = email.toLowerCase();
    const usernameLower = username.toLowerCase();

    const existingEmail = await User.findOne({ email: emailLower });
    if (existingEmail) {
      return res.status(400).json({
        success: false,
        message: "Email already exists",
      });
    }

    const existingUsername = await User.findOne({ username: usernameLower });
    if (existingUsername) {
      return res.status(400).json({
        success: false,
        message: "Username already exists",
      });
    }

    const secretId = makeSecretId(usernameLower);

    const existingSecretId = await User.findOne({ secretId });
    if (existingSecretId) {
      return res.status(400).json({
        success: false,
        message: "Try another username",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      username: usernameLower,
      email: emailLower,
      phone: phone || "",
      password: hashedPassword,
      secretId,
      privacy: privacy || "Private Profile",
    });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.status(201).json({
      success: true,
      message: "Signup successful",
      token,
      user: {
        _id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        phone: user.phone,
        secretId: user.secretId,
        bio: user.bio,
        profileImage: user.profileImage,
        privacy: user.privacy,
        blocked: user.blocked,
        blockedReason: user.blockedReason,
        isAdmin: user.isAdmin,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Signup failed",
      error: error.message,
    });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername || !password) {
      return res.status(400).json({
        success: false,
        message: "Email/Username and password required",
      });
    }

    const value = emailOrUsername.toLowerCase();

    const user = await User.findOne({
      $or: [
        { email: value },
        { username: value },
        { secretId: value },
      ],
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.blocked) {
      return res.status(403).json({
        success: false,
        message: "Your account is blocked",
        blocked: true,
        blockedReason: user.blockedReason || "",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Wrong password",
      });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user: {
        _id: user._id,
        name: user.name,
        username: user.username,
        email: user.email,
        phone: user.phone,
        secretId: user.secretId,
        bio: user.bio,
        profileImage: user.profileImage,
        privacy: user.privacy,
        blocked: user.blocked,
        blockedReason: user.blockedReason,
        isAdmin: user.isAdmin,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Login failed",
      error: error.message,
    });
  }
});

// Logged in user profile
app.get("/api/auth/me", auth, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: req.user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Profile fetch failed",
      error: error.message,
    });
  }
});

// Update profile
app.put("/api/auth/profile", auth, async (req, res) => {
  try {
    const { name, bio, profileImage, phone, privacy } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      {
        ...(name !== undefined && { name }),
        ...(bio !== undefined && { bio }),
        ...(profileImage !== undefined && { profileImage }),
        ...(phone !== undefined && { phone }),
        ...(privacy !== undefined && { privacy }),
      },
      { new: true }
    ).select("-password");

    res.status(200).json({
      success: true,
      message: "Profile updated",
      user: updatedUser,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Profile update failed",
      error: error.message,
    });
  }
});

// ======================
// Post Routes
// ======================

// Create post
app.post("/api/posts", auth, async (req, res) => {
  try {
    const { text, image } = req.body;

    if ((!text || !text.trim()) && !image) {
      return res.status(400).json({
        success: false,
        message: "Text or image is required",
      });
    }

    const post = await Post.create({
      user: req.user._id,
      authorName: req.user.name,
      secretId: req.user.secretId || "",
      email: req.user.email || "",
      phone: req.user.phone || "",
      text: text || "",
      image: image || "",
    });

    const populatedPost = await Post.findById(post._id)
      .populate("user", "name username profileImage secretId privacy blocked")
      .populate("comments.user", "name username profileImage");

    res.status(201).json({
      success: true,
      message: "Post created successfully",
      post: populatedPost,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Post creation failed",
      error: error.message,
    });
  }
});

// Get all posts
app.get("/api/posts", async (req, res) => {
  try {
    const posts = await Post.find()
      .populate("user", "name username profileImage secretId privacy blocked")
      .populate("comments.user", "name username profileImage")
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: posts.length,
      posts,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Posts fetch failed",
      error: error.message,
    });
  }
});

// Get my posts
app.get("/api/posts/me", auth, async (req, res) => {
  try {
    const posts = await Post.find({ user: req.user._id })
      .populate("user", "name username profileImage secretId privacy blocked")
      .populate("comments.user", "name username profileImage")
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: posts.length,
      posts,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "My posts fetch failed",
      error: error.message,
    });
  }
});

// Like / Unlike post
app.put("/api/posts/:id/like", auth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({
        success: false,
        message: "Post not found",
      });
    }

    const alreadyLiked = post.likes.some(
      (likeUserId) => likeUserId.toString() === req.user._id.toString()
    );

    if (alreadyLiked) {
      post.likes = post.likes.filter(
        (likeUserId) => likeUserId.toString() !== req.user._id.toString()
      );
    } else {
      post.likes.push(req.user._id);
    }

    await post.save();

    const updatedPost = await Post.findById(req.params.id)
      .populate("user", "name username profileImage secretId privacy blocked")
      .populate("comments.user", "name username profileImage");

    res.status(200).json({
      success: true,
      message: alreadyLiked ? "Post unliked" : "Post liked",
      post: updatedPost,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Like action failed",
      error: error.message,
    });
  }
});

// Add comment
app.post("/api/posts/:id/comment", auth, async (req, res) => {
  try {
    const { text } = req.body;

    if (!text || !text.trim()) {
      return res.status(400).json({
        success: false,
        message: "Comment text is required",
      });
    }

    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({
        success: false,
        message: "Post not found",
      });
    }

    post.comments.push({
      user: req.user._id,
      name: req.user.name,
      text,
    });

    await post.save();

    const updatedPost = await Post.findById(req.params.id)
      .populate("user", "name username profileImage secretId privacy blocked")
      .populate("comments.user", "name username profileImage");

    res.status(201).json({
      success: true,
      message: "Comment added",
      post: updatedPost,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Comment failed",
      error: error.message,
    });
  }
});

// Share count
app.put("/api/posts/:id/share", async (req, res) => {
  try {
    const post = await Post.findByIdAndUpdate(
      req.params.id,
      { $inc: { shares: 1 } },
      { new: true }
    )
      .populate("user", "name username profileImage secretId privacy blocked")
      .populate("comments.user", "name username profileImage");

    if (!post) {
      return res.status(404).json({
        success: false,
        message: "Post not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Share counted",
      post,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Share failed",
      error: error.message,
    });
  }
});

// Delete own post
app.delete("/api/posts/:id", auth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({
        success: false,
        message: "Post not found",
      });
    }

    if (post.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: "You can delete only your own post",
      });
    }

    await Post.findByIdAndDelete(req.params.id);

    res.status(200).json({
      success: true,
      message: "Post deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Delete failed",
      error: error.message,
    });
  }
});

// ======================
// Admin Routes
// ======================

// Get all users
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: users.length,
      users,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Users fetch failed",
      error: error.message,
    });
  }
});

// Get all posts
app.get("/api/admin/posts", adminAuth, async (req, res) => {
  try {
    const posts = await Post.find()
      .populate("user", "name username email phone profileImage secretId privacy blocked")
      .populate("comments.user", "name username profileImage")
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: posts.length,
      posts,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Admin posts fetch failed",
      error: error.message,
    });
  }
});

// Get admin stats
app.get("/api/admin/stats", adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const blockedUsers = await User.countDocuments({ blocked: true });
    const totalPosts = await Post.countDocuments();
    const totalImagePosts = await Post.countDocuments({ image: { $ne: "" } });
    const totalWordPosts = await Post.countDocuments({ text: { $ne: "" } });

    res.status(200).json({
      success: true,
      stats: {
        totalUsers,
        blockedUsers,
        activeUsers: totalUsers - blockedUsers,
        totalPosts,
        totalImagePosts,
        totalWordPosts,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Stats fetch failed",
      error: error.message,
    });
  }
});

// Block / Unblock user
app.put("/api/admin/users/:id/block", adminAuth, async (req, res) => {
  try {
    const { blocked, blockedReason } = req.body;

    const user = await User.findById(req.params.id).select("-password");

      if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.isAdmin) {
      return res.status(400).json({
        success: false,
        message: "Admin user cannot be blocked",
      });
    }

    user.blocked = !!blocked;
    user.blockedReason = blocked ? (blockedReason || "Blocked by admin") : "";
    await user.save();

      res.status(200).json({
      success: true,
      message: blocked ? "User blocked successfully" : "User unblocked successfully",
      user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Block action failed",
      error: error.message,
    });
  }
});

// Delete any post by admin
app.delete("/api/admin/posts/:id", adminAuth, async (req, res) => {
  try {
    const post = await Post.findByIdAndDelete(req.params.id);
    
    if (!post) {
      return res.status(404).json({
        success: false,
        message: "Post not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Post deleted by admin",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Admin post delete failed",
      error: error.message,
    });
  }
});

// Delete user + all posts
app.delete("/api/admin/users/:id", adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.isAdmin) {
      return res.status(400).json({
        success: false,
        message: "Admin user cannot be deleted",
      });
    }

    await Post.deleteMany({ user: req.params.id });
    await User.findByIdAndDelete(req.params.id);

    res.status(200).json({
      success: true,
      message: "User and related posts deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Admin user delete failed",
      error: error.message,
    });
  }
});

// ======================
// Start Server
// ======================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});
