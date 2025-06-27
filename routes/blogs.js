const express = require('express');
const Blog = require('../models/Blog');
const  upload  = require('../utils/multer'); // Import multer configuration from utils
const path = require('path');

const router = express.Router();

// Create a new blog
router.post('/', upload.any(), async (req, res) => {
  const { title, content, category } = req.body;
  const mediaFiles = req.files; // Get the uploaded files (array)

  try {
    if (!mediaFiles || mediaFiles.length === 0) {
      return res.status(400).send('No media files uploaded');
    }

    const mediaUrls = [];

    // Process each uploaded file
    for (const media of mediaFiles) {
      // Save the media file as a Buffer directly into MongoDB
      const mediaUrl = {
        filename: media.originalname,
        fileType: media.mimetype,
        fileData: media.buffer,  // Store the media file as Buffer
      };

      mediaUrls.push(mediaUrl);  // Add the media file URL object to the array
    }

    // Create and save the blog
    const newBlog = new Blog({
      title,
      content,
      category,
      mediaUrls,  // Store the array of media file URLs (or file data as Buffer)
    });

    await newBlog.save();
    res.status(201).json(newBlog);  // Return the created blog

  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Get all blogs
router.get('/', async (req, res) => {
  try {
    const blogs = await Blog.find().populate('category');
    res.json(blogs);
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
