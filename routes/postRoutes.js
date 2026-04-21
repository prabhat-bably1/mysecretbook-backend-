const express = require("express");
const Post = require("../models/Post");
const { authUser } = require("../middleware/auth");

const router = express.Router();

router.post("/add-word", authUser, async (req, res) => {
  try {
    const { text } = req.body;

    if (!text || !text.trim()) {
      return res.status(400).json({ message: "Text is required" });
    }

    const post = new Post({
      userId: req.user._id,
      secretId: req.user.secretId,
      email: req.user.email,
      phone: req.user.phone,
      type: "word",
      text: text.trim()
    });

    await post.save();

    return res.json({
      message: "Word saved successfully",
      post
    });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to save word",
      error: error.message
    });
  }
});

router.post("/add-image", authUser, async (req, res) => {
  try {
    const { imageUrl, text } = req.body;

    if (!imageUrl || !imageUrl.trim()) {
      return res.status(400).json({ message: "Image URL is required" });
    }

    const post = new Post({
      userId: req.user._id,
      secretId: req.user.secretId,
      email: req.user.email,
      phone: req.user.phone,
      type: "image",
      imageUrl: imageUrl.trim(),
      text: text || ""
    });

    await post.save();

    return res.json({
      message: "Image saved successfully",
      post
    });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to save image",
      error: error.message
    });
  }
});

router.get("/my-posts", authUser, async (req, res) => {
  try {
    const posts = await Post.find({ userId: req.user._id }).sort({ createdAt: -1 });
    return res.json({ posts });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to get posts",
      error: error.message
    });
  }
});

router.delete("/delete/:id", authUser, async (req, res) => {
  try {
    const post = await Post.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id
    });

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

module.exports = router;
