const express = require("express");
const User = require("../models/User");
const Post = require("../models/Post");
const { authAdmin } = require("../middleware/auth");

const router = express.Router();

router.get("/users", authAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 }).select("-password");
    return res.json({ users });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to fetch users",
      error: error.message
    });
  }
});

router.get("/posts", authAdmin, async (req, res) => {
  try {
    const posts = await Post.find().sort({ createdAt: -1 });
    return res.json({ posts });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to fetch posts",
      error: error.message
    });
  }
});

router.patch("/block-user/:id", authAdmin, async (req, res) => {
  try {
    const { blocked, blockedReason } = req.body;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      {
        blocked: !!blocked,
        blockedReason: blocked ? (blockedReason || "Blocked by admin") : ""
      },
      { new: true }
    ).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.json({
      message: blocked ? "User blocked successfully" : "User unblocked successfully",
      user
    });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to update user block status",
      error: error.message
    });
  }
});

router.delete("/delete-user/:id", authAdmin, async (req, res) => {
  try {
    await Post.deleteMany({ userId: req.params.id });
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.json({ message: "User and related posts deleted successfully" });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to delete user",
      error: error.message
    });
  }
});

router.delete("/delete-post/:id", authAdmin, async (req, res) => {
  try {
    const post = await Post.findByIdAndDelete(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "Post not found" });
    }

    return res.json({ message: "Post deleted successfully" });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to delete post",
      error: error.message
    });
  }
});

router.get("/stats", authAdmin, async (req, res) => {
  try {
    const users = await User.countDocuments();
    const blockedUsers = await User.countDocuments({ blocked: true });
    const wordPosts = await Post.countDocuments({ type: "word" });
    const imagePosts = await Post.countDocuments({ type: "image" });

    return res.json({
      totalUsers: users,
      blockedUsers,
      activeUsers: users - blockedUsers,
      totalWords: wordPosts,
      totalImages: imagePosts
    });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to fetch stats",
      error: error.message
    });
  }
});

module.exports = router;
