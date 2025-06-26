const express = require('express');
const Blog = require('../models/Blog');
const router = express.Router();

// Get all blogs
router.get('/', async (req, res) => {
  try {
    const blogs = await Blog.find().populate('category');
    res.json(blogs);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Create a new blog
router.post('/', async (req, res) => {
  const { title, content, category } = req.body;
  try {
    const newBlog = new Blog({ title, content, category });
    await newBlog.save();
    res.status(201).json(newBlog);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Update a blog
router.put('/:id', async (req, res) => {
  const { title, content, category } = req.body;
  try {
    const updatedBlog = await Blog.findByIdAndUpdate(
      req.params.id,
      { title, content, category },
      { new: true }
    );
    res.json(updatedBlog);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Delete a blog
router.delete('/:id', async (req, res) => {
  try {
    await Blog.findByIdAndDelete(req.params.id);
    res.json({ message: 'Blog deleted successfully' });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

module.exports = router;
